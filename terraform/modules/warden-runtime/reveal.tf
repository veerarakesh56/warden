# The masked values of an incident and their reveal (src/warden/reveal.py): a records page of its own, served by the
# approval function - the only one whose role may open the vault key (vault.tf). One route, GET: the reveal is a form
# sent to itself with an anti-forgery token bound to the reader's sign-in cookie, and it is recorded before any value
# is shown.
resource "aws_apigatewayv2_route" "reveal" {
  api_id    = aws_apigatewayv2_api.front.id
  route_key = "GET /r/{incident}/masked"
  target    = "integrations/${aws_apigatewayv2_integration.front["approval"].id}"
}
