variable "enableEncryption" {
    default = true
}

variable "cidr_blocks" {
    type = list(string)
    default = ["10.0.0.0/2"]
}