<!-- For the README's "How it works" section -->

[![WARDEN: how it fits together](../docs/diagrams/architecture-overview.png)](../docs/diagrams/architecture-overview.svg)

*An alarm reaches WARDEN's front door, its five trust zones read, ask the model, check and report, and nothing
changes until a person signs the exact plan with a passkey.*

[![WARDEN: one incident, end to end](../docs/diagrams/incident-flow.png)](../docs/diagrams/incident-flow.svg)

*One incident from alarm to signed record, column by trust zone, with every safety check marked.*

<!-- For the README's "Architecture" section -->

[![WARDEN detailed architecture, 1 of 2: the runtime](../docs/diagrams/architecture-detailed-1.png)](../docs/diagrams/architecture-detailed-1.svg)

*Every runtime component by its real name: the front door, Temporal Cloud, each zone's service with its secrets and
the roles it may assume, and WARDEN's own data and alarms.*

[![WARDEN detailed architecture, 2 of 2: identities, environments and outside services](../docs/diagrams/architecture-detailed-2.png)](../docs/diagrams/architecture-detailed-2.svg)

*Who may do what in each environment, and every outside service WARDEN talks to.*

[![WARDEN: how changes are checked and delivered](../docs/diagrams/delivery.png)](../docs/diagrams/delivery.svg)

*main runs CI only; dev and prod deploy from their own branches through OIDC, infrastructure only from a reviewed
plan that Helios has checked.*

Each image is drawn from the code (origin/main de1cbcd); click one for the sharp SVG. The editable sources are in [`docs/diagrams/`](../docs/diagrams/README.md).
