# Threat model

What can attack WARDEN or go wrong through it, at each place where trust changes, and what stops it. Written with
STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege) over the
components as the code and Terraform build them on `main`. Every mitigation that is built names the file that
implements it and the test that proves it (a planned one has neither yet); [tests/test_threat_model.py](../tests/test_threat_model.py) fails CI if a cited file or test
does not exist or is skipped.

Three kinds of status are used, and nothing else:

- **built and tested**: the code exists and a test proves it (cited);
- **built, not proven live**: the code and its test exist, but it has not yet run in a live cloud window;
- **planned**: not built. A planned mitigation gives none of its protection today; where a row names a weaker
  control that works now (a person stopping the act service, today's shorter retention), only that control holds.

The full list of failure modes, with what is still open, is [the failure-mode register](FAILURE-MODES.md). This page
is the security view of the same system; where a row of the register covers a threat, its id is given (for example
`S5`).

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| The watched AWS accounts and Kubernetes clusters | WARDEN can change them. A wrong or forged change is the worst outcome. |
| The right to approve a change | Whoever approves decides what WARDEN does in production. |
| The audit | The only record of what WARDEN saw, decided and did. If it can be rewritten, nothing WARDEN says can be trusted. |
| Secrets: the model key, Temporal keys, Slack and GitHub tokens, webhook secrets | Each one opens a door into WARDEN or a service it uses. |
| Evidence read from the watched systems | It may hold customer data, credentials and internal names. |
| The people on call | WARDEN must not hide an incident, flood them, or talk them into a bad fix. |

## 2. Components and trust boundaries

```
 watched AWS env ──alarm/event──▶ EventBridge ─▶ alarm Lambda ─┐
 Alertmanager / Datadog ─HTTPS─▶ API Gateway ─▶ webhook Lambda ─┤
                                                                ▼
                                     Temporal Cloud ◀──▶ ECS workers, one per zone
                                                          core · read · llm · notify · act
   watched env ◀── reader role ── read zone                │
   model API   ◀── redacted facts ── llm zone              │
   Slack, GitHub ◀── outbound gate ── notify zone          │
   watched env ◀── per-plan actor session ── act zone      │
                                                          ▼
                    audit (Aurora) ── KMS signer ── S3 Object Lock anchors ── CloudTrail witness
 approver's browser ─HTTPS─▶ API Gateway ─▶ approval Lambda (Slack sign-in + passkey) ─▶ Temporal signal
 GitHub repository ─▶ GitHub Actions (OIDC) ─▶ deploy roles ─▶ AWS
```

The trust boundaries (TB) used below:

| TB | Boundary | What crosses it |
|---|---|---|
| TB1 | Watched environments to intake | Alarm changes, AWS service events, Alertmanager and Datadog webhooks |
| TB2 | Evidence to the model | Logs, events, configuration: attacker-controlled text |
| TB3 | The model's answer to WARDEN's decision | A diagnosis and one proposed action |
| TB4 | WARDEN to people (Slack, GitHub, terminal, MCP) | Reports, approval requests, answers |
| TB5 | People to WARDEN (approval page, discussion channel) | Approvals, denials, notes, questions |
| TB6 | The act zone to the watched environments | One approved change |
| TB7 | Workers to Temporal Cloud | Workflow state |
| TB8 | Workers to the audit, KMS and S3 | The record |
| TB9 | The repository to the deploy pipelines and AWS | Code, images, infrastructure |
| TB10 | The planned code-writing path to GitHub | Pull requests WARDEN would write (planned) |

## 3. Threats and mitigations

### TB1: intake

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| S | A forged alert through the webhook (S5) | Alertmanager and Datadog reach WARDEN only through API Gateway. The gateway's own request authorizer admits a route only with its bearer secret from Secrets Manager (two during rotation), compared in constant time, and fails closed; the Lambda behind it checks the secret again; a firing alert is acted on only if Alertmanager's own API lists it as active | [webhook_auth.py](../terraform/modules/warden-runtime/webhook_auth/webhook_auth.py), [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf), [webhooks.py](../src/warden/webhooks.py), [lambdas.py](../src/warden/lambdas.py); tests/test_iac_leftovers_sonar.py::test_the_webhook_routes_pass_the_gateway_only_with_their_bearer_secret, tests/test_iac_leftovers_sonar.py::test_the_webhook_gate_admits_the_routes_secret_only_and_fails_closed, tests/test_webhooks_s5.py::test_only_a_caller_with_the_secret_gets_in_and_learns_nothing_else, tests/test_webhooks_s5.py::test_a_forged_alert_alertmanager_never_fired_is_not_acted_on, tests/test_datadog_alerts_g10z.py::test_only_a_monitor_datadog_itself_says_is_alerting_starts_anything | built and tested |
| S | An alert claims one environment for another's resource (S6) | The target's own environment, read from the platform, must equal the incident's, at plan and again before apply | [catalog.py](../src/warden/catalog.py); tests/test_remediation_target.py::test_a_target_whose_own_environment_is_another_is_refused, tests/test_remediation_target.py::test_the_environment_moving_after_approval_stops_the_apply | built and tested |
| S | An alert about WARDEN itself steers WARDEN to change its own runtime (N7) | An alert about WARDEN's own components goes to a person; a fix of them is refused | [verifier.py](../src/warden/verifier.py) P22, [activities.py](../src/warden/activities.py); tests/test_self_target_n7.py::test_an_alert_about_wardens_own_runtime_goes_to_a_person_whatever_is_proposed, tests/test_self_target_n7.py::test_a_remediation_of_wardens_own_components_is_refused | built and tested |
| T | The alert's name and description carry instructions (M10, N3) | The model sees the alert's rule id only; the summary becomes quarantined evidence | [evidence.py](../src/warden/evidence.py), [quarantine.py](../src/warden/quarantine.py); tests/test_alert_text.py::test_the_model_sees_the_alert_rule_id_and_never_its_prose | built and tested |
| D | A flood of webhooks or an alarm storm (N10, C2, C21) | API Gateway throttles every route; a repeat signals the open incident; open incidents are capped; a flapping alarm goes to a person without the model | [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf) (throttling), [intake.py](../src/warden/intake.py); tests/test_webhooks_s5.py::test_a_flood_is_refused_before_it_is_read, tests/test_runtime_module_g6.py::test_the_api_throttles_logs_and_routes_exactly_what_the_page_and_the_webhook_serve, tests/test_intake.py::test_a_repeat_signals_the_open_incident_and_a_storm_is_capped, tests/test_intake.py::test_a_flapping_alarm_goes_to_a_person_without_the_model | built and tested |
| D | An alarm is lost on the way in | EventBridge retries for an hour, then the lost-alarm queue pages. An error *inside* the alarm Lambda (for example Temporal down) now pages too, through the Lambda-errors self-alarm, and the page repeats until acknowledged. Gap, open: that alarm event itself is retried by Lambda and then dropped - the function has no on-failure destination, so a person must look at the alarm (the WARDEN-down runbook, B29) | [frontdoor.tf](../terraform/modules/warden-runtime/frontdoor.tf), [paging.tf](../terraform/modules/warden-runtime/paging.tf); tests/test_runtime_module_g6.py::test_the_alarm_rule_sends_what_the_alarm_lambda_accepts_and_a_lost_alarm_pages, tests/test_paging.py::test_every_self_alarm_reaches_the_pager_and_paused_workers_page_nobody | built and tested |

### TB2: evidence to the model (prompt injection)

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| T, E | Text an attacker wrote into a log line, an event or a resource field tells the model what to do | Untrusted text is reduced to typed facts that cannot carry a sentence; the planted line never reaches the model and does not change the action | [quarantine.py](../src/warden/quarantine.py); tests/test_quarantine.py::test_an_injected_log_line_never_reaches_the_model_and_does_not_change_the_action, tests/test_injection_corpus.py::test_no_injection_payload_reaches_the_model_or_changes_the_action | built and tested |
| T | The same, in a form the quarantine misses | An optional local classifier (Llama Prompt Guard 2) scans untrusted lines; a flagged line sends the incident to a person (P16). It is a tripwire, never a filter that clears text | [tripwire.py](../src/warden/tripwire.py); tests/test_tripwire.py::test_a_flagged_line_escalates_an_otherwise_approved_fix, tests/test_tripwire.py::test_required_mode_escalates_unless_the_detector_actually_ran | built and tested |
| T | Free-text configuration (a Lambda's description, tags, environment values) carries instructions (M11) | Descriptions and tags are never read; an environment value is shown only under an allowlisted name | [aws_stack.py](../src/warden/aws_stack.py); tests/test_free_text_m11.py::test_a_functions_description_never_becomes_evidence, tests/test_aws_stack.py::test_an_environment_value_is_shown_only_under_a_configuration_name | built and tested |
| T | Memory: a past record, a discussion or a runbook poisoned earlier steers a new diagnosis (G10-48) | No diagnosis reads a discussion or a past answer; past incidents reach the model only as fixed facts the signed record vouches for, and only when switched on | [history.py](../src/warden/history.py); tests/test_memory_trust_g10x.py::test_no_diagnosis_reads_a_record_a_discussion_or_a_past_answer, tests/test_memory_trust_g10x.py::test_a_diagnosis_is_shown_only_past_runs_the_signed_record_vouches_for | built and tested |
| I | Secrets or personal data in evidence reach the model provider | Redaction masks credentials, keys, tokens and identifiers before any model call. Pattern based: a secret in a format no pattern knows is not caught | [redaction.py](../src/warden/redaction.py); tests/test_redaction.py::test_credentials_are_masked_jwt_and_api_keys, tests/test_graph_redaction.py::test_deploy_identifiers_do_not_reach_the_model | built and tested |
| E | The model process itself reaches a credential or a tool | The model CLI runs with no tool, no MCP server, no operator settings and no credential but its own | [providers.py](../src/warden/providers.py); tests/test_claude_cli_provider.py::test_no_tool_no_mcp_server_and_no_operator_setting_is_loaded, tests/test_claude_cli_provider.py::test_no_credential_in_the_parent_environment_reaches_the_model_process | built and tested |

### TB3: the model's answer to WARDEN's decision

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| T | The model invents evidence or a target (P13, P14) | Every citation must quote an evidence id that holds it; a target must be one WARDEN read from live state | [grounding.py](../src/warden/grounding.py); tests/test_grounding.py::test_an_invented_id_escalates, tests/test_grounding.py::test_a_misquote_escalates, tests/test_catalog.py::test_a_target_must_be_one_warden_read_from_live_state | built and tested |
| E | The model proposes a dangerous write | The model can only choose from a closed catalogue of small, reversible changes with bounded parameters; deletes, failovers and schema changes are not in it | [catalog.py](../src/warden/catalog.py); tests/test_catalog.py::test_every_entry_is_well_formed_and_nothing_forbidden_is_in_it, tests/test_catalog.py::test_scaling_is_up_only_and_by_at_most_two | built and tested |
| E | A confident wrong answer is let through | Deterministic policies (P0-P33) decide, not the model; a second opinion that disagrees escalates; nothing runs without an approval | [verifier.py](../src/warden/verifier.py); tests/test_verifier.py::test_clean_case_is_held_for_a_human_not_auto_run, tests/test_verifier.py::test_p3_refuses_to_act_without_evidence | built and tested |
| T | The model, its prompt or its CLI changes silently (M15, E6, M20) | Exact model ids only; the prompt is pinned by hash; a model must pass the replay qualification before use | [providers.py](../src/warden/providers.py), [llm.py](../src/warden/llm.py); tests/test_model_pin_m15.py::test_an_alias_that_moves_is_refused, tests/test_prompt_pin_e6.py::test_the_prompt_is_the_one_the_models_were_qualified_with, tests/test_provider_qualified_m20.py::test_an_unmeasured_model_is_refused | built and tested |
| D | The model provider is down, slow or the budget is spent (M19, M18) | Rules-only escalation to a person; a per-incident and a daily cap | [graph.py](../src/warden/graph.py), [llm.py](../src/warden/llm.py); tests/test_degraded_m19.py::test_with_no_model_the_incident_is_escalated_by_rules_alone, tests/test_degraded_m19.py::test_the_daily_cap_stops_the_model_across_incidents | built and tested |

### TB4: WARDEN to people (reports, Slack, GitHub, terminal, MCP)

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| I | A secret leaves in a report or a log | The outbound gate checks every way out and withholds a message that still holds a secret; the worker's own log is gated | [gate.py](../src/warden/gate.py); tests/test_gate.py::test_a_secret_still_in_the_outgoing_text_blocks_the_message, tests/test_egress.py::test_the_worker_log_is_gated | built and tested |
| T | Model text plants a link, an image or a command for a person to click or run | The gate removes links, images and markup the model wrote and withholds write commands | [gate.py](../src/warden/gate.py); tests/test_gate.py::test_a_planted_image_or_link_echoed_by_the_model_never_reaches_the_slack_payload, tests/test_discuss_g10v.py::test_a_model_answer_with_a_fenced_command_is_posted_without_a_code_block | built and tested |
| S | A fake "WARDEN" message in Slack (S17) | Each message names the incident and the head of its signed record, which `warden audit show` can match | [activities.py](../src/warden/activities.py), [chatops.py](../src/warden/chatops.py); tests/test_message_footer_s17.py::test_the_message_names_the_incident_and_the_head_of_its_signed_record | built and tested |
| E | The MCP server is used to approve or execute (B10, B13) | No MCP tool can approve, sign, reset or execute; a caller's claimed evidence escalates | [mcp_server.py](../src/warden/mcp_server.py); tests/test_mcp_workflows.py::test_no_tool_can_approve_sign_reset_or_execute_and_none_takes_a_credential, tests/test_mcp_server.py::test_a_clean_case_on_claimed_evidence_is_escalated_never_approved | built and tested |
| I | A credential WARDEN sends to GitHub, Slack, Datadog or Grafana is carried by a redirect to another host (Python's urllib copies the Authorization header to wherever a 3xx points) | Every credentialed call goes through one opener: https only, and a redirect is followed only to the same scheme, host and port; any other redirect is refused and read as a failed read. A source check fails CI if a module sends a credential header through bare urllib (PR #168) | [web.py](../src/warden/web.py); tests/test_web_redirects.py::test_a_redirect_to_another_host_is_refused_and_the_credential_never_reaches_it, tests/test_web_redirects.py::test_a_redirect_to_another_port_on_the_same_host_is_refused, tests/test_web_redirects.py::test_no_module_sends_a_credential_header_through_bare_urllib | built and tested |
| D | WARDEN's own trouble is paged once and nobody sees it | Every self-alarm (heartbeat, synthetic run, worker errors and stops, the kill switch, the lost-alarm queue, an unapproved actor session, an approver-list change, the Lambdas' errors and throttles, the audit database, a Temporal key near its end) reaches a pager of its own - no image, no VPC, no database - that repeats the page every 15 minutes in Slack and by email until an approver acknowledges it with a passkey | [paging.tf](../terraform/modules/warden-runtime/paging.tf), [pager.py](../terraform/modules/warden-runtime/pager/pager.py), [paging.py](../src/warden/paging.py); tests/test_paging.py::test_a_page_repeats_every_15_minutes_saying_how_long_and_why_until_acknowledged, tests/test_paging.py::test_every_self_alarm_reaches_the_pager_and_paused_workers_page_nobody, tests/test_paging.py::test_an_approvers_passkey_acknowledges_exactly_the_pages_shown_on_the_record | built and tested |
| I | WARDEN tells GitHub an account id while reading a commit | The commit behind a deploy is read without sending an account id | [timeline.py](../src/warden/timeline.py) `CommitReader`; tests/test_grafana_g10y.py::test_the_commit_behind_a_deploy_is_read_and_an_account_id_never_leaves_for_github | built and tested |

### TB5: people to WARDEN (approval page, passkeys, discussion)

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| S | Someone approves as an approver (H6) | Every approval is a WebAuthn passkey signature over the plan (workflow, plan hash, tier, single-use nonce, expiry), re-verified by the workflow against the approver's enrolled key; Slack sign-in first says which member is at the page; a link is per approver, 15 minutes, used once | [passkeys.py](../src/warden/passkeys.py), [approval_page.py](../src/warden/approval_page.py), [slack_login.py](../src/warden/slack_login.py); tests/test_passkey_workflow_h6.py::test_a_passkey_approval_of_another_plan_is_refused, tests/test_passkey_workflow_h6.py::test_a_key_the_approver_never_enrolled_is_refused, tests/test_slack_login_g10q.py::test_another_slack_member_or_a_sign_in_begun_elsewhere_opens_nothing, tests/test_approval_page.py::test_someone_elses_passkey_sees_nothing | built and tested |
| S | A replayed approval, a cloned passkey, one person counted twice | Single-use nonces and challenges, signature counters that may not go back, distinct approvers per tier | [passkeys.py](../src/warden/passkeys.py), [activities.py](../src/warden/activities.py); tests/test_passkey_workflow_h6.py::test_a_replayed_passkey_approval_is_refused, tests/test_passkey_workflow_h6.py::test_a_cloned_passkey_whose_counter_restarted_is_refused_in_a_later_run, tests/test_passkey_workflow_h6.py::test_one_person_cannot_be_two_approvers_with_two_fresh_passkey_approvals | built and tested |
| T | The approver list is changed to add an approver (G10-33) | The list lives in SSM; every write to it is recorded in the audit and pages, even when the audit cannot be written | [lambdas.py](../src/warden/lambdas.py), [witness.tf](../terraform/modules/warden-runtime/witness.tf); tests/test_actor_use_g6.py::test_every_write_to_the_approver_list_is_recorded_and_pages_made_or_refused, tests/test_actor_use_g6.py::test_a_list_write_still_pages_when_the_audit_cannot_be_written | built and tested |
| T | The approval page is framed, scripted or cached | No inline or third-party script, no framing, HSTS, no caching, no referrer. The page is public by design: it shows nothing until a passkey says who is looking | [approval_page.py](../src/warden/approval_page.py); tests/test_approval_page.py::test_every_response_is_locked_down, tests/test_approval_page.py::test_the_link_shows_nothing_until_a_passkey_says_who_is_looking | built and tested |
| E | Someone in the discussion channel talks WARDEN into a change | Anyone may ask; the thread is data; the model has no tool; only an enrolled approver may ask for a new plan, which still needs a passkey approval | [discuss.py](../src/warden/discuss.py); tests/test_discuss_g10v.py::test_the_whole_conversation_runs_as_a_workflow_and_changes_nothing, tests/test_discuss_g10v.py::test_an_approvers_new_plan_is_a_fresh_diagnosis_once_an_hour_and_anyone_elses_is_refused | built and tested |
| E | The bench approver (a test key for `dev`) approves outside `dev` | It may approve only T1 and T2 plans in a nonprod environment and is refused anywhere else | [approvals.py](../src/warden/approvals.py); tests/test_bench_approver.py::test_a_plan_outside_its_environments_or_tiers_is_neither_shown_nor_approved | built and tested |
| R | An approver says they never approved | The signed passkey assertion and the approver's id are in the signed audit; records show who approved or denied, how and when | [audit.py](../src/warden/audit.py), [records.py](../src/warden/records.py); tests/test_outcome_told_g10j.py::test_a_denial_says_who_denied_how_and_when_as_an_approval_does | built and tested |
| E | Approval fatigue: a person signs without reading (H1) | A hasty approval is recorded as such; the plan's before and after are shown; T2 and T3 need the target typed | [activities.py](../src/warden/activities.py), [approval_page.py](../src/warden/approval_page.py); tests/test_approval_fatigue_h1.py::test_an_approval_signed_seconds_after_the_plan_is_recorded_as_hasty, tests/test_approval_page.py::test_a_mistyped_target_sends_nothing | built and tested |
| E | Eldane, the AI critic, approves a bad fix in `dev` on its own (dev is autonomous through Eldane by the owner's decision) | Eldane runs after the gate, the bounds and the policies, so it can only add a "no"; it uses the other model from the one that diagnosed, reads the evidence and the plan before WARDEN's reasoning, and approves only when both passes agree; its approval counts only at L2, which prod never reaches; it never approves a plan on WARDEN itself or its guardrails; a person's "no" stops an Eldane-approved plan before apply; a failed fix, a rollback, a harmful decision, a model change or a missed catch trial demotes it at once, and only a person's signed re-enable restores it; the record and the channel say it was an AI | [eldane.py](../src/warden/eldane.py), [autonomy.py](../src/warden/autonomy.py); tests/test_eldane_autonomy.py::test_eldane_always_uses_the_other_model_from_the_one_that_diagnosed, tests/test_eldane_autonomy.py::test_the_first_pass_is_blind_and_only_an_agreement_sees_warden_s_reasoning, tests/test_eldane_autonomy.py::test_prod_is_never_autonomous_whatever_the_file_or_the_record_says, tests/test_eldane_autonomy.py::test_eldane_s_own_agreement_never_approves_a_plan_on_warden_itself, tests/test_eldane_autonomy.py::test_a_person_s_no_stops_an_eldane_approved_plan_before_it_is_applied, tests/test_eldane_autonomy.py::test_a_critic_that_misses_a_planted_plan_loses_its_approvals, tests/test_eldane_autonomy.py::test_after_a_demotion_only_a_person_s_signed_re_enable_restores_l2, tests/test_eldane_autonomy.py::test_at_l2_eldane_alone_approves_a_dev_fix_and_the_record_says_it_was_an_ai | built and tested |

### TB6: the act zone to the watched environments

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| E | The worker that applies changes holds broad, standing power | No standing role: a per-plan actor session of at most 900 seconds, whose session policy allows only the plan's actions on the plan's exact resources, naming the approvers and the incident | [identity.py](../src/warden/identity.py); tests/test_identity_ap5.py::test_the_session_allows_only_the_plans_actions_on_its_exact_resources, tests/test_identity_ap5.py::test_no_session_without_an_approver_or_with_a_value_sts_would_refuse | built and tested |
| E | An actor role is used without an approval | Every actor session is checked against the audit through CloudTrail; one without its approval pages a person | [actor_use.py](../src/warden/actor_use.py); tests/test_actor_use_g6.py::test_the_lambda_pages_an_unapproved_session_and_records_it | built and tested |
| T | The target changes between approval and apply, or the code or catalogue changes (O5) | Live state is re-checked before apply; a change means a new plan; a plan made under other code or another catalogue is not applied | [activities.py](../src/warden/activities.py) `plan_hash`, [catalog.py](../src/warden/catalog.py); tests/test_remediation_target.py::test_a_plan_made_under_other_code_or_another_catalogue_is_not_applied, tests/test_remediation_target.py::test_a_plan_carried_to_another_target_is_refused_at_apply | built and tested |
| D | WARDEN makes things worse, or loops (C1, C8, B12) | Bounds per service and action class, a cool-down per target, a breaker that trips the kill switch after two failed checks in an hour; the kill switch is checked inside every apply | [bounds.py](../src/warden/bounds.py); tests/test_bounds.py::test_two_failed_success_checks_in_an_hour_trip_the_kill_switch, tests/test_bounds.py::test_a_service_gets_three_changes_an_hour_then_waits, tests/test_intake.py::test_an_alarm_during_the_verify_window_rolls_the_fix_back | built and tested |
| E | The kill switch is reset by someone who should not | Only a signed approval of that specific trip resets it | [bounds.py](../src/warden/bounds.py); tests/test_bounds.py::test_only_a_signed_approval_of_this_trip_resets_it_and_only_once, tests/test_killswitch_reset_g10m.py::test_an_approvers_passkey_resets_the_switch_after_showing_every_trip | built and tested |
| E | The kill switch cannot be reached when it matters | A second kill switch as an IAM deny on the actor role, independent of WARDEN's code and database (B18): every action is denied unless the role's tag says exactly `off`, the role cannot tag itself and no session can override the tag. It covers AWS calls only - a Kubernetes fix is authorised by the cluster, where WARDEN's own switch still applies. A person can also set the act service to 0 tasks (the WARDEN-down runbook, B29) | [kill-switch.json](../iam/templates/kill-switch.json), [iam_kill_switch.py](../scripts/iam_kill_switch.py); tests/test_iam_kill_switch.py::test_every_action_is_denied_unless_the_tag_says_exactly_off, tests/test_iam_kill_switch.py::test_the_role_cannot_turn_its_own_switch_and_no_session_can_override_it | built, not proven live |
| T | Two runs write the same target at once (B20) | A single-writer lock per target on the audit: a second run's fix or undo of a held target is refused at apply and changes nothing; the lock ends with its run or its time limit | [locks.py](../src/warden/locks.py); tests/test_target_lock_b20.py::test_two_workers_on_one_audit_never_both_take_the_target, tests/test_target_lock_b20.py::test_a_second_fix_of_a_held_target_is_refused_at_apply_and_changes_nothing, tests/test_target_lock_b20.py::test_an_undo_while_another_run_holds_the_target_is_not_sent | built and tested |
| E | A reader or actor role reaches another environment or makes itself admin | Each environment's roles sit inside a permissions boundary held to that environment; no role trust can be rewritten; deploy roles cannot create unbounded roles | [boundary.json](../iam/templates/boundary.json), [deploy-guard.json](../iam/templates/deploy-guard.json); tests/test_env_iam.py::test_the_boundary_holds_every_environment_to_itself, tests/test_env_iam.py::test_no_role_trust_can_be_rewritten, tests/test_no_role_can_make_itself_admin.py::test_every_deploy_role_has_a_guard_for_the_roles_without_a_boundary | built and tested |
| E | Kubernetes: the remediator patches more than it may | RBAC plus an admission policy narrow what it may patch. Gaps, open in the register: `metadata.managedFields` is not held (R8-O3), and enforcement on EKS is unconfirmed (R7-O3) | [platforms/k8s.py](../src/warden/platforms/k8s.py), [remediation-rbac.yaml](../k8s/remediation-rbac.yaml); tests/test_platform_k8s.py::test_an_admission_policy_narrows_what_the_remediator_may_patch | built and tested |

### TB7: workers to Temporal Cloud

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| I | Workflow history exposes evidence or secrets (S2) | Every payload is encrypted with AES-256-GCM, bound to its workflow, before it leaves the worker; Temporal holds ciphertext only | [codec.py](../src/warden/codec.py); tests/test_incident_workflow.py::test_with_encryption_nothing_redacted_is_readable_in_history, tests/test_codec.py::test_a_ciphertext_is_bound_to_its_workflow | built and tested |
| T | A forged signal or payload | The codec refuses a changed or forged ciphertext; the workflow re-verifies every approval itself | [codec.py](../src/warden/codec.py), [workflows.py](../src/warden/workflows.py), [activities.py](../src/warden/activities.py); tests/test_codec.py::test_a_forged_ciphertext_is_refused_not_raised, tests/test_remediation_workflow.py::test_a_forged_approval_is_refused_and_a_real_one_still_works, tests/test_passkey_workflow_h6.py::test_a_passkey_approval_of_another_plan_is_refused | built and tested |
| S, E | One leaked Temporal key reaches everything (S15) | API key over TLS; each ECS zone has its own key and its own role. The three front door Lambdas that reach Temporal share one key: kept on purpose, owner decision 2026-10-20 (cost), so a leak of it reaches what those Lambdas can, not the zones' work; the zones' own keys are not yet proven live (S15b). Sending the key only to the namespace's own endpoint (B23) is PR #102, in review | [runtime_base.py](../src/warden/runtime_base.py) `connect`, [iam.tf](../terraform/modules/warden-runtime/iam.tf); tests/test_temporal_auth_s15.py::test_temporal_cloud_is_reached_with_the_api_key_over_tls, tests/test_temporal_auth_s15.py::test_a_remote_server_without_a_key_is_refused_before_any_connection, tests/test_runtime_module_g6.py::test_each_zone_reads_exactly_the_secrets_its_worker_loads | built, not proven live |

### TB8: the record

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| T, R | Someone with the database rewrites history (S12) | A hash chain with signed checkpoints; the signer is a KMS key WARDEN cannot export; checkpoints are anchored to S3 Object Lock in COMPLIANCE mode; CloudTrail witnesses every signature | [audit.py](../src/warden/audit.py); tests/test_audit_log.py::test_rewriting_a_row_and_recomputing_every_later_hash_is_caught_by_the_signature, tests/test_audit_anchor_s12.py::test_a_history_rewritten_and_re_signed_with_the_key_is_caught_by_its_anchors | built and tested |
| R | The anchors' lock is too short to matter, or the rows cannot be restored | At least 180 days of audit retention (B19). Decided 2026-10-20 for the backups: 35 days of automated backups and one monthly AWS Backup copy kept 180 days. Built in PR #91 (in review). Today Object Lock on the anchors lasts `anchor_retention_days`, 1 day by default, backups 7 days and logs 90 days ([the data-retention page](DATA-RETENTION.md), B33) | [anchors.tf](../terraform/modules/warden-runtime/anchors.tf) | planned |
| D | The audit database is lost (O4) | Backups with point-in-time recovery, deletion protection, a final snapshot. A restore has never been drilled: the drill is planned (O4b) | [aurora.tf](../terraform/modules/warden-runtime/aurora.tf); tests/test_runtime_module_g6.py::test_the_audit_database_keeps_point_in_time_recovery_and_is_reached_by_the_runtime_only | built and tested |

### TB9: repository, CI and deploy pipelines

| STRIDE | Threat | Mitigation | Evidence | Status |
|---|---|---|---|---|
| T | A malicious change to the prompt, a policy or the catalogue through a pull request (N8) | Their hashes are pinned in `docs/safety-pins.sha256`, and CODEOWNERS names a reviewer for each | [safety_pins.py](../scripts/safety_pins.py), [CODEOWNERS](../.github/CODEOWNERS); tests/test_tamper_n8.py::test_a_change_to_a_pinned_file_breaks_the_pins, tests/test_tamper_n8.py::test_codeowners_names_a_reviewer_for_every_pinned_path | built and tested |
| T | Supply chain: a moved action tag, an unpinned package, an image swapped (S9) | Actions pinned to commit SHAs; hash-locked installs; images by digest; WARDEN's runtime image built before any credential, signed with cosign and given provenance; only a signed and attested image is deployed | [runtime.yml](../.github/workflows/runtime.yml), [uv.lock](../uv.lock); tests/test_ci_lanes.py::test_every_action_is_pinned_to_a_full_commit_sha, tests/test_runtime_pipeline_s9.py::test_nothing_is_deployed_that_this_workflow_did_not_sign_and_attest | built and tested |
| E | A pull request or `main` reaches AWS | Nothing that can reach AWS runs on `main` or on a pull request; each environment deploys only from its own branch through its own GitHub Environment by OIDC | [_infra-deploy.yml](../.github/workflows/_infra-deploy.yml), [_apps-deploy.yml](../.github/workflows/_apps-deploy.yml), [iam/](../iam/); tests/test_ci_lanes.py::test_nothing_that_can_reach_aws_runs_on_main_or_on_a_pull_request, tests/test_env_iam.py::test_only_the_same_named_github_environment_may_assume | built and tested |
| T | An infrastructure change breaks a stack's resilience | Helios judges the Terraform plan against the stack's failure scenarios and refuses a regression; Helios gets none of the job's credentials | [helios_gate.py](../scripts/helios_gate.py), [_infra-validate.yml](../.github/workflows/_infra-validate.yml); tests/test_helios_gate_r56.py::test_main_refuses_a_regressing_plan_and_passes_an_unchanged_one, tests/test_helios_gate_r56.py::test_helios_gets_none_of_the_job_credentials | built and tested |
| I | An account id leaks in a public log | Account-holding values are GitHub secrets, never variables | [runtime.yml](../.github/workflows/runtime.yml), [_infra-deploy.yml](../.github/workflows/_infra-deploy.yml); tests/test_ci_account_values_are_secrets.py::test_no_workflow_reads_an_account_holding_value_as_a_variable | built and tested |

### TB10: the code-writing path (B4) - planned

WARDEN does not write code on `main` today. The code-writing path (B4) lets it open small pull requests: first
reverts of the deployed commit a rollback diagnosed, then small fixes from code-review findings. It is built in four
pull requests, all in review: phase 1, `code_fix` per environment and the deterministic code gate (PR #101); phase 2,
WARDEN's GitHub App identity (PR #120); phase 3, revert pull requests (PR #127); phase 4, the `autofix-regression` CI
job and auto-merge, switched off (PR #145). **Until they merge, everything in this table is planned**: none of it
protects anything on `main`, and none of the path exists there to attack.

| STRIDE | Threat | Planned mitigation | Where |
|---|---|---|---|
| S | WARDEN's commits are mistaken for a person's, or a person's for WARDEN's | A GitHub App identity of its own, an installation token, commits signed through `createCommitOnBranch` | PR #120 |
| T, E | Prompt injection through findings: a code-review finding, an issue or a log line tells the model to add a backdoor | Findings are evidence like any other (quarantined, untrusted); a deterministic code gate checks every diff: a size limit, an allowed-paths list, no workflow, IAM, secret or CODEOWNERS file, no new dependency, tests that cover the change | PR #101 |
| T | Supply chain through WARDEN: a new or changed dependency | The code gate refuses any new dependency; lock files are not in the allowed paths | PR #101 |
| E | Privilege: the App's token is used beyond one pull request | Least-privilege App permissions, a short-lived installation token, the App id and key in their own secret slots; no merge right in prod | PR #120 |
| E | An automatic merge of a bad change | `code_fix: off / propose / auto` per environment, prod never `auto`; in `dev` a pull request merges itself only after all CI, CodeRabbit, SonarCloud and Eldane are green (owner decision, 2026-10-21); prod always a person; an `autofix-regression` CI job | PRs #101, #145 |
| R | Nobody can tell what WARDEN wrote and why | Each pull request links its incident's record page and the audit row that proposed it | PRs #120, #127 |

## 4. Other planned protections

| What | Covers | Where it is tracked |
|---|---|---|
| Exact actions instead of wildcards in the deploy policy; the runtime's own task-execution policy | Least privilege for deploys | B22, PR #85 (in review) |
| A code guard: the workers and Lambdas refuse any Temporal address that is not the configured Temporal Cloud namespace endpoint (owner decision 2026-10-20; in code, not network-enforced - the security group stays limited to port 7233). Today the address is used as configured | A worker sent to another Temporal server | B23, PR #102 (in review) |
| Checking the actor role's permissions before asking for approval | An approved plan AWS then refuses | B12, PR #76 (in review) |
| A check for a deploy or a pull request between the fix and its rollback | Rolling back someone else's change | B21, PR #84 (in review) |
| At least 180 days of audit retention | Anchors and backups that end too soon | B19, PR #91 (in review) |
| WARDEN's code-writing path | See TB10 | B4, PRs #101, #120, #127, #145 (in review) |

## 5. What this model does not cover

- A compromised AWS account root, GitHub organisation owner, Slack workspace admin, Temporal Cloud account or model
  provider. WARDEN trusts each of them for what they host.
- An approver who is coerced or acts in bad faith with their own passkey. Two approvers per tier are supported by the
  code; this install has one ([README.md](../README.md#what-it-is-not-and-its-limits)).
- Secrets in a format no redaction pattern knows.
- The watched applications' own security.
