/*******
        * Author is Dongze Wu
        * Last modified date: 24 Sep, 2022
                                          *******/
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), send(), and recv() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <openssl/aes.h> /* for AES algorithm */
#include <openssl/rand.h> /* for random number */
#include <openssl/evp.h>
#include <fstream>
#include <iostream>
#include <cstdio>

using namespace std;

#define Buff 4096   //Size of buffer

// Error handling function
void DieWithError(string errorMessage)
{
    cout << errorMessage << endl;
    exit(1);
}

// Send the ciphertext file with a header of iv to server
void sfile(string fname,int sock)
{
    int i;
    ifstream inf(fname);
    string data( (std::istreambuf_iterator<char>(inf) ),
                       (std::istreambuf_iterator<char>()) );
    /* Send the string to the server */
    if (send(sock, data.c_str(), data.size(), 0) != data.size())
        DieWithError("send() sent a different number of bytes than expected");
    cout << data.size() << " bytes written." << endl;
    inf.close();
    //This is to get the file name
    const char *name = fname.c_str();
    //after sending file rm the ciphertext file since we don't need to store the file in remote mode
    remove(name);
}


//KEY generation return KEY generated
unsigned char * key_gene(char* pw)
{
    unsigned char salt[] = {'S','o','d','i','u','m','C','h','l','o','r','i','d','e'};
    //string salt = "SodiumChloride";
    size_t i;
    unsigned char *KEY;
    KEY = (unsigned char *) malloc(sizeof(unsigned char) * 32);
    if( PKCS5_PBKDF2_HMAC(pw, strlen(pw), salt, sizeof(salt),4096,EVP_sha3_256(),32, KEY) != 0 ){
        printf("KEY: "); 
        for(i=0;i<32;i++){ 
            printf("%02X ", KEY[i]); 
        } printf("\n");
    }
    else
        fprintf(stderr, "Hash failed\n");
    return(KEY);
}

//AES GCM mode
int enc(unsigned char *plaintext, int plaintext_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag,char fname[],int flag,int sock)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    //Initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        DieWithError("Initialise context failed!");

    // Initialise the encryption operation. 
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        DieWithError("Initialise encryption failed!");
    
    //Set IV length if default 12 bytes (96 bits) is not appropriate
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        DieWithError("Set IV length failed!");

    // Initialise key and IV
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        DieWithError("Initialise key and IV failed!");

    //Provide the message to be encrypted, and obtain the encrypted output.
    //EVP_EncryptUpdate can be called multiple times if necessary
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        DieWithError("Plaintext processing failed!");
    ciphertext_len = len;

    //Finalise the encryption. Normally ciphertext bytes may be written at
    //this stage, but this does not occur in GCM mode
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        DieWithError("Encryption failed");
    ciphertext_len += len;

    // Get the tag 
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        DieWithError("Get Tag failed");

    cout << "Successfully encrypted file!" << endl;
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
    

    //Write the cipher text to file '.ufsec'
    char tail[] = ".ufsec";
    string ename = strcat(fname,tail);
    ifstream inf(ename);
    ofstream ouf(ename,ios::binary);
    if(inf){
        DieWithError("The file already exists!\nFile written abort!\n");
    }
    ouf.write((const char*)iv,16);
    ouf.write((const char*)tag,16);
    ouf.write((const char*)ciphertext,ciphertext_len);
    ouf.close();
    cout << "Ciphertext stored into "<<ename<<" successfully!"<<endl;
    // flag 1 means it runs in remote mode so send the file
    if(flag == 1) {
        sfile(ename,sock);
    }
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

//local mode
int localmode(char *fname)
{
            //read the file as the plaintext
            ifstream inf(fname);
            if(!inf){
                cout<<"File not exist!"<<endl;
                return 33;
            }
            string p( (std::istreambuf_iterator<char>(inf) ),
                       (std::istreambuf_iterator<char>()) );
            p.c_str();
            inf.close();
            unsigned char *plaintext = (unsigned char*) p.c_str();
            char password[18];
            cout << "Please enter your password:" << endl;
            cin >> password;
            unsigned char *KEY= key_gene(password);
            //Generate random iv
            unsigned char iv[16];
            RAND_bytes(iv,sizeof(iv));
            size_t iv_len = 16;
            unsigned char ciphertext [65535];
            unsigned char tag[16];
            int plaintext_len = sizeof(plaintext);

            enc(plaintext,strlen ((char *)plaintext), KEY, iv,iv_len,
                                 ciphertext,tag,fname,0,0);
            return 0;

}

int main(int argc, char *argv[])
{
    int sock;                        /* Socket descriptor */
    struct sockaddr_in ServAddr; /* Echo server address */
    unsigned short ServPort;     /* Echo server port */
    char *servIP;                    /* Server IP address (dotted quad) */
    char *mode;                  /* mode for local or remote */
    char *fname;                /* filename of the file */
    if ((argc < 3) || (argc > 4))    /* Test for correct number of arguments */
    {
       printf( "Invalid command!\nUsage: <./program> <File name> <mode> [<IP:Port>]\n");
       exit(1);
    }

    fname = argv[1];             /* First arg: server IP address (dotted quad) */
    mode = argv[2];         /* Second arg: string to echo */

    //Local mode
    if (argc == 3){
        if (strcmp(argv[2],"-l") != 0 )  /* when the command is wrong*/
            printf( "Invalid command!\nUsage: <./program> <File name> <mode> [<IP:Port>]\n");
        else{
            int res = localmode(fname);
            return res;
        }
    }

    //Remote mode
    if(argc == 4){
        if(strcmp(argv[2],"-d") != 0)       /* when the command is wrong*/
            DieWithError("Invalid command!\nUsage: <./program> <File name> <mode> [<IP:Port>]\n");
        else{
            char *tok;
            tok = strtok(argv[3],":");
            servIP = tok;       // obtain the ip address for communication
            ServPort = atoi(strtok(NULL,":"));       // obtain the port number for communication
            string ip = tok;
             // Here is the connection and transmission part
    
            // Create a reliable, stream socket using TCP 
            if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
                DieWithError("socket() failed");
            printf("Socket generate successfully!\n");
            // Construct the server address structure 
            memset(&ServAddr, 0, sizeof(ServAddr));     /* Zero out structure */
            ServAddr.sin_family      = AF_INET;             /* Internet address family */
            ServAddr.sin_addr.s_addr = inet_addr(servIP);   /* Server IP address */
            ServAddr.sin_port        = htons(ServPort); /* Server port */
            // Establish the connection to the echo server
            if (connect(sock, (struct sockaddr *) &ServAddr, sizeof(ServAddr)) < 0)
                DieWithError("connect() failed");
            printf("Connection established!\n");

            //encrypt the file
            ifstream inf(fname);
            if(!inf){
                cout<<"File not exist!"<<endl;
                return 33;
            }
            char password[18];
            printf("Enter your password:\n");
            scanf("%s",password);
            unsigned char *KEY= key_gene(password);
            string p( (std::istreambuf_iterator<char>(inf) ),
                       (std::istreambuf_iterator<char>()    ) );
            p.c_str();
            inf.close();
            unsigned char *plaintext = (unsigned char*) p.c_str();

            //Generate random iv
            unsigned char iv[16];
            RAND_bytes(iv,16);
            size_t iv_len = 16;
            unsigned char ciphertext[65535];
            unsigned char tag[16];
            int plaintext_len = sizeof(plaintext);
            enc(plaintext,strlen ((char *)plaintext), KEY, iv,iv_len,
                                 ciphertext,tag,fname,1,sock);
            cout << "Transmitting to " << ip << ":" << ServPort << " ..." << endl;
            close(sock);
            cout << "Done" <<endl;
            exit(0);
            }
    }
}
