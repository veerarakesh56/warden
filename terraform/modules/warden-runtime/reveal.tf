# The masked values of an incident and their reveal (src/warden/reveal.py): a records page of its own, served by the
# approval function - the only one whose role may open the vault key (vault.tf). GET shows the values by id and the
# form; POST is the reveal itself, so the reason and the chosen values travel in the body, never in an address. The
# form carries an anti-forgery token bound to the reader's sign-in cookie, only an approver may reveal, and every
# reveal is recorded before any value is shown.
resource "aws_apigatewayv2_route" "reveal" {
  for_each  = toset(["GET", "POST"])
  api_id    = aws_apigatewayv2_api.front.id
  route_key = "${each.key} /r/{incident}/masked"
  target    = "integrations/${aws_apigatewayv2_integration.front["approval"].id}"
}
