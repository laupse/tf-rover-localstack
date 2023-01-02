variable "name" {
    type = string
    default = "inpulse"
}

variable "vpc_id" {
    type = string
    default = "vpc-06586f43bc0d1982f"
}

variable "subnet_ids" {
    type = list(string)
    default = [ "subnet-00f6d803f9ae69789", "subnet-0adfa3cfffac381d1" ]
}
