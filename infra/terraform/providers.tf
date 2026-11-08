provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = var.project
      Owner     = "person-a"
      ManagedBy = "terraform"
    }
  }
}
