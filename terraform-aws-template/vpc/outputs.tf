output "zontal_app_sg" {
    value = {
        name = aws_security_group.zontal_app_sg.name
        id = aws_security_group.zontal_app_sg.id
    }
}

output "lambda_sg" {
    value = {
        name = aws_security_group.lambda_sg.name
        id = aws_security_group.lambda_sg.id
    }
}

output "zontal_app_public_sg" {
    value = {
        name = aws_security_group.zontal_app_public_sg.name
        id = aws_security_group.zontal_app_public_sg.id
    }
}
