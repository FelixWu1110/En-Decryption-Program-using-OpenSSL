/*******
        * Author is Dongze Wu
        * Last modified date: 24 Sep, 2022
                                          *******/
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), bind(), and connect() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <openssl/aes.h> /* for AES algorithm */
#include <openssl/rand.h> /* for random number */
#include <openssl/evp.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <vector>

#define MAXPENDING 20   /* Maximum outstanding connection requests */
#define SIZE 10000  /* Size of receive buffer */

//Deal with errors
void DieWithError(std::string errorMessage)
{
    std::cout << errorMessage << std::endl;
    exit(1);
}

//KEY generation return KEY generated
unsigned char * key_gene(char *pw)
{
    unsigned char salt[] = {'S','o','d','i','u','m','C','h','l','o','r','i','d','e'};
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

//Decryption
int dec(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext,std::string fname)
{
    EVP_CIPHER_CTX *ctx;
    int len,plaintext_len,ret;
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        DieWithError("Initialise context failed!");

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        DieWithError("Initialise context failed!");

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        DieWithError("Initialise context failed!");

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        DieWithError("Initialise context failed!");

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        DieWithError("Initialise context failed!");
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        DieWithError("Initialise context failed!");

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    if (plaintext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        plaintext[plaintext_len] = '\0';

        /* Show the decrypted text */
        std::cout << "Decrypted text is:" << std::endl << plaintext << std::endl;

        
        //store the decrypted text
        std::ofstream ouf(fname);

        ouf << plaintext;
        ouf.close();
    } else {
        printf("Decryption failed\n");
    }

    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } 
    else {
        /* Verify failed */
        return -1;
    }
}

//get data function
std::string gdata(int ClntSock,char *fname)
{
    char *buff = new char[65535];
    std::ofstream ouf(fname, std::ifstream::binary);
    int size = recv(ClntSock,buff,SIZE,0);
    if (size < 0)
        DieWithError("recv() failed");
      while (size > 0)      /* zero indicates end of transmission */
    {
        /* See if there is more data to receive */
        if ((size = recv(ClntSock, buff, SIZE, 0)) < 0)
            DieWithError("recv() failed");
    }
        close(ClntSock);    /* Close client socket */
        //Store the data into a file
        std::cout << "Buff length is: " <<strlen(buff) <<std::endl;
        ouf.write(buff,strlen(buff));
        ouf.close();
    return fname;
}

//local mode
int localmode(char *fname)
{   
    
            //read the iv and ciphertext from the file to decrypt
            std::ifstream inf(fname,std::ios::binary);
            if(!inf){
                std::cout << "File not exist!" << std::endl;
                return 33;
            }
            char password[18];
            std::cout << "Enter your password:" << std::endl;
            std::cin >> password;
            unsigned char *KEY = key_gene(password);


            /* To get the iv from the file */
            // get the starting position
            std::streampos start1 = inf.tellg();
            // go to the end
            inf.seekg(16);
            // get the ending position
            std::streampos end1 = inf.tellg();
            // go back to the start
            inf.seekg(0);
            //Store the iv to the vector named hea 
            std::vector<char> hea;
            hea.resize(static_cast<size_t>(end1 - start1));
            inf.read(&hea[0],hea.size());
            unsigned char *iv = (unsigned char *)hea.data();
           
            /* To get the tag from the file */
            inf.seekg(16);
            std::streampos start2 = inf.tellg();
            // go to the end
            inf.seekg(32);
            // get the ending position
            std::streampos end2 = inf.tellg();
            // go back to the start
            inf.seekg(start2);
            //Store the tag to the vector named gtag  
            std::vector<char> gtag;
            gtag.resize(static_cast<size_t>(end2 - start2));
            // read it in
            inf.read(&gtag[0], gtag.size());
            unsigned char *tag = (unsigned char*) gtag.data();
    
            /* To get the ciphertext from the file */
            // get the starting position
            inf.seekg(32);
            std::streampos start = inf.tellg();
            // go to the end
            inf.seekg(0,std::ios::end);
            // get the ending position
            std::streampos end = inf.tellg();
            // go back to the start
            inf.seekg(start);
            //Store the ciphertext to the vector named contents  
            std::vector<char> contents;
            contents.resize(static_cast<size_t>(end - start));
            // read it in
            inf.read(&contents[0], contents.size());
            inf.close();
            unsigned char *ciphertext = (unsigned char*) contents.data();

            //print for clarity
            int i, j;
            for (i=0; i<contents.size(); i+=16) {
                printf("%04x - ", i);
                for (j=0; j<16; j++) { 
                    if (i+j < contents.size())
                        printf("%02x ", ciphertext[i+j]);
                    else
                        printf("   ");
                }
                printf(" ");
                for (j=0; j<16; j++) {
                    if (i+j < contents.size())
                        printf("%c", isprint(ciphertext[i+j]) ? ciphertext[i+j] : '.');
                }
                printf("\n");
            }
            
            std::string ename =fname;
            ename.erase(ename.end() - 6,ename.end());
            size_t iv_len = 16;
            //unsigned char tag[16];
            unsigned char plaintext[65535];
            int ciphertext_len = contents.size();
            dec(ciphertext,ciphertext_len,
                tag,
                KEY,
                iv,iv_len,
                plaintext,ename);  
            return 0;
}


int main(int argc, char *argv[])
{
    int servSock;                    // Socket descriptor for server 
    int clntSock;                    // Socket descriptor for client
    struct sockaddr_in echoServAddr; // Local address 
    struct sockaddr_in echoClntAddr;
    unsigned short echoServPort;     // Server port
    unsigned int clntLen;            // Length of client address data structure
    char *mode;                  // mode for local or remote
    char *fname;                // filename of the file */

    if (argc < 3 || argc > 4)     // Test for correct number of arguments
    {
        printf("Parameters wrong!\nUsage: <./program> <File name> <mode> [<Port>]\n");
        exit(1);
    }

    fname = argv[1];        // Filename 
    mode = argv[2];         // Running mode

    /* Local mode with -l */
    if (argc == 3){
        if (strcmp(argv[2],"-l") != 0)      /* when the command is wrong*/
            DieWithError("Invalid command!\nUsage: <./program> <File name> <mode> [<Port>]\n");
        else{
            //Local mode
            int res = localmode(fname);
            return res;
        }
    }

     /* Remote mode with -d port */
    if(argc == 4){
        if(strcmp(argv[2],"-d") != 0)       /* when the command is wrong*/
            DieWithError("Invalid command!\nUsage: <./program> <File name> <mode> [<Port>]\n");
        else{

            char password[18];
            std::cout << "Enter your password:" << std::endl;
            std::cin >> password;
            unsigned char *KEY = key_gene(password);

            echoServPort = atoi(argv[3]);  /* First arg:  local port */
            /* Create socket for incoming connections */
            if ((servSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
                DieWithError("socket() failed");
            /* Construct local address structure */
            memset(&echoServAddr, 0, sizeof(echoServAddr));   /* Zero out structure */
            echoServAddr.sin_family = AF_INET;                /* Internet address family */
            echoServAddr.sin_addr.s_addr = htonl(INADDR_ANY); /* Any incoming interface */
            echoServAddr.sin_port = htons(echoServPort);      /* Local port */
            /* Bind to the local address */
            if (bind(servSock, (struct sockaddr *)&echoServAddr,sizeof(echoServAddr)) < 0)
                DieWithError("bind() failed");
            /* Mark the socket so it will listen for incoming connections */
            if (listen(servSock, MAXPENDING) < 0)
                DieWithError("listen() failed");
            printf("Listening to incoming connection\n");

            /* Set the size of the in-out parameter */
            clntLen = sizeof(echoClntAddr);
            /* Wait for a client to connect */
            if ((clntSock = accept(servSock, (struct sockaddr *) &echoClntAddr, &clntLen)) < 0)
                DieWithError("accept() failed");
            printf("Client %s connected\n",inet_ntoa(echoClntAddr.sin_addr));
            std::string ename = gdata(clntSock,fname);            

            //read the file for decrypt
            std::ifstream inf(ename,std::ios::binary);
            if(!inf){
                std::cout << "File not exist!" << std::endl;
                return 33;
            }
            
            /* To get the iv from the file to decrypt */
            // get the starting position
            std::streampos start1 = inf.tellg();
            // go to the end
            inf.seekg(16);
            // get the ending position
            std::streampos end1 = inf.tellg();
            // go back to the start
            inf.seekg(0);
            //Store the iv to the vector named hea 
            std::vector<char> hea;
            hea.resize(static_cast<size_t>(end1 - start1));
            inf.read(&hea[0],hea.size());
            unsigned char *iv = (unsigned char *)hea.data();
            
            
             /* To get the tag from the file */
            inf.seekg(16);
            std::streampos start2 = inf.tellg();
            // go to the end
            inf.seekg(32);
            // get the ending position
            std::streampos end2 = inf.tellg();
            // go back to the start
            inf.seekg(start2);
            //Store the tag to the vector named gtag  
            std::vector<char> gtag;
            gtag.resize(static_cast<size_t>(end2 - start2));
            // read it in
            inf.read(&gtag[0], gtag.size());
            unsigned char *tag = (unsigned char*) gtag.data();
            
            /* To get the ciphertext from the file */
            // get the starting position
            inf.seekg(32);
            std::streampos start = inf.tellg();
            // go to the end
            inf.seekg(0,std::ios::end);
            // get the ending position
            std::streampos end = inf.tellg();
            // go back to the start
            inf.seekg(start);
            //Store the ciphertext to the vector named contents  
            std::vector<char> contents;
            contents.resize(static_cast<size_t>(end - start));
            // read it in
            inf.read(&contents[0], contents.size());
            inf.close();
            unsigned char *ciphertext = (unsigned char*) contents.data();

            std::cout<< "INBOUND file:" <<std::endl << hea.size() + contents.size() << " bytes received..." << std::endl;
            //print for clarity
            int i, j;
            for (i=0; i<contents.size(); i+=16) {
                printf("%04x - ", i);
                for (j=0; j<16; j++) { 
                    if (i+j < contents.size())
                        printf("%02x ", ciphertext[i+j]);
                    else
                        printf("   ");
                }
                printf(" ");
                for (j=0; j<16; j++) {
                    if (i+j < contents.size())
                        printf("%c", isprint(ciphertext[i+j]) ? ciphertext[i+j] : '.');
                }
                printf("\n");
            }
    
            size_t iv_len = 16;
            unsigned char plaintext[65535];
            int ciphertext_len = contents.size();
            dec(ciphertext,ciphertext_len,
                tag,
                KEY,
                iv,iv_len,
                plaintext,ename); 
            /* clntSock is connected to a client! */
            printf("Client %s handled successfully!\n", inet_ntoa(echoClntAddr.sin_addr));
        }   // end else
    }   //end if(argc == 4)
    
}
