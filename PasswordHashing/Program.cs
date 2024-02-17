Console.WriteLine("Start");


string password = "12345678";

var hashedPassword = PasswordHasher.String.Hash(password);
Console.WriteLine(hashedPassword.Hash);
Console.WriteLine(hashedPassword.Salt);

Console.WriteLine(PasswordHasher.String.Verify(password, hashedPassword.Hash, hashedPassword.Salt));


