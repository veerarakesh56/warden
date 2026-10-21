terraform {
  required_version = ">= 1.15.0, < 1.17.0" # CI pins 1.16.4; a later minor is a deliberate change
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0, < 7.0" }
  }
}
