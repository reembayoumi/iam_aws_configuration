variable "region" {
  type = string
  default = "eu-north-1"
}

variable "account_id" {
  type = string
  default = "654654361264"
}

variable "vpc_id" {
  default = "vpc-081d54ac6c69a30d1"
}


variable "sso_users" {
  description = "A map of SSO users to be created"
  type = map(object({
    display_name = string
    user_name    = string
    given_name   = string
    family_name  = string
    email        = string
  }))
  default = {
    user1 = {
      display_name = "Reem Bayoumi"
      user_name    = "reem.bayoumi"
      given_name   = "reem"
      family_name  = "Bayoumi"
      email        = "reem.bayoumi@gmail.com"
    }
    user2 = {
      display_name = "HR"
      user_name    = "HR"
      given_name   = "Uier"
      family_name  = "Essple"
      email        = "user.HR@gmail.com"
    }
 user3 = {
      display_name = "Programmer"
      user_name    = "Programmer"
      given_name   = "Andres"
      family_name  = "John"
      email        = "user.Andres@gmail.com"
    }

  }
}
