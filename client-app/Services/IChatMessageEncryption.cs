namespace Client_app.Services
{
    public interface IChatMessageEncryption
    {
        string Encrypt(string plaintext);
        string Decrypt(string storedValue);
    }
}
