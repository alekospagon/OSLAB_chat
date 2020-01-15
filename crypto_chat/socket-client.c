/*
 * client-cryptodev.c
 * Encrypted TCP/IP communication using sockets
 *
 * PAGWNHS ALEXANDROS - SVEZENTSEV DAVID
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <crypto/cryptodev.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"



unsigned char input_buffer[256];
unsigned char key[] = "davidsvezencev";
unsigned char iv[] = "pagwnsalexandros123";


/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *input_buffer, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = write(fd, input_buffer, cnt);
                if (ret < 0)
                        return ret;
                input_buffer += ret;
                cnt -= ret;
        }

        return orig_cnt;
}


/* Encrypt data placed in input_buffer and store back */
int cipher_encrypt(int cipher_fd,struct session_op sess)
{
	/* ENCRYPT PARAMETERS */
    int i=0;
	struct crypt_op cryp;
	struct {
		unsigned char encrypted[DATA_SIZE];
	} data;
    memset(&cryp, 0, sizeof(cryp));

    /* init crypto struct to being encryption */
    cryp.ses = sess.ses;					//take session
	cryp.len = sizeof(input_buffer);		//size of buffer
	cryp.src = input_buffer;				//char * where data is
	cryp.dst = data.encrypted;				//where to store
	cryp.iv  =  iv;							//init vector
	cryp.op  = COP_ENCRYPT;					//TODO: encrypt

	//IO-control: use /dev/crypto to encrypt
    if (ioctl(cipher_fd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return 1;
	}

	//store encrypted data back into input_buffer
	memset(input_buffer, '\0', 256);
	for (i = 0; i < DATA_SIZE; i++) {
		input_buffer[i] = data.encrypted[i];
	}
	return 0;
}


int cipher_decrypt(int cipher_fd,struct session_op sess)
{
	/* DECRYPT PARAMETERS */
    int i=0;
	struct crypt_op cryp;
	struct {
	unsigned char decrypted[DATA_SIZE];

	} data;
    memset(&cryp, 0, sizeof(cryp));

    /* init crypto struct to being decryption */
    cryp.ses = sess.ses;				//take session
	cryp.len = sizeof(input_buffer);	//size of buffer
	cryp.src = input_buffer;			//char * where data is
	cryp.dst = data.decrypted;			//where to store
	cryp.iv  =  iv;						//init vector
	cryp.op  = COP_DECRYPT;				//TODO: decrypt

	//IO-control: use /dev/crypto to decrypt
		if (ioctl(cipher_fd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return 1;
	}

	/* clear buffer -> when whole buffer is encrypted
	 * it may leave junk after re-write. So clear it 
	 * first */
	memset(input_buffer, '\0', 256);

	//store decrypted data back into input_buffer
   	for (i = 0; i < DATA_SIZE; i++) {
		input_buffer[i] = data.decrypted[i];
	}

    return 0;
}

int main(int argc, char *argv[])
{	
	/* ========== PARAMETERS ========== */	
	struct session_op sess;
	struct hostent *hp;
	struct sockaddr_in sa;
	char *hostname;
    int socket_fd,polling,port,cryptodev_fd;
    ssize_t input_bytes;
	fd_set set_of_files_to_be_polled;


	if (argc < 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}

	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */


	/* Create TCP/IP socket, used as main chat channel */
	if ((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;		// On internet
	sa.sin_port   = htons(port);	// to network short 
	// take address from hp->h_addr as it was resolved by DNS
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));

	// Connect
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(socket_fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");
    
    //OPEN DAT FILE
	cryptodev_fd = open("/dev/crypto", O_RDWR);
	if (cryptodev_fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
		}

	//prepare session
	memset(&sess, 0, sizeof(sess));

	// Get crypto session for AES128
	// Init session
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE; 		//socket-common.h
	sess.key    = key;
	
	// Create session
	if (ioctl(cryptodev_fd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}

	/* Prepare set */
	FD_ZERO(&set_of_files_to_be_polled);
	fprintf(stdout, CYAN "Client: " RESET);
	fflush(stdout);


    /* Read answer and write it to standard output */
    for (;;) {

    	// Monitor my input and Servers output
        FD_SET(socket_fd,&set_of_files_to_be_polled);
		FD_SET(0,&set_of_files_to_be_polled);

		/* Begin monitoring file descriptors */
		polling = select(socket_fd+1,&set_of_files_to_be_polled,NULL,NULL,NULL);
		if((polling == -1)){
			fprintf(stdout,"Error in select!");
			fflush(stdout);
			exit(1);
		}	

		// Server's message
        if(FD_ISSET(socket_fd,&set_of_files_to_be_polled)){
        	// Read it
        	memset(input_buffer, '\0', 256);	// Clear buffer first
        	input_bytes = read(socket_fd,input_buffer,sizeof(input_buffer));

        	// Seomthing went wrong || Server died
			if (input_bytes <= 0) {
				// Something went wrong
				if (input_bytes < 0)
					perror("read from remote peer failed");
				// Server died: he sent zero bytes
				else
					fprintf(stderr, "\nBob went away\n");
				// Anyway: leave
				break;
			}

			fprintf(stdout,"\nServer: ");
			fflush(stdout);

			// Decrypt his message
			if(cipher_decrypt(cryptodev_fd,sess) != 0){
				perror("\nSomething went wrong when decrypting your message!");
			}
			// Print it
           	if(insist_write(1,input_buffer,input_bytes) != input_bytes){
					perror("Something went wrong when writing to the stdout!");
			}
			// Prepare to write again
			fprintf(stdout, CYAN "Client: " RESET );
			fflush(stdout);
		}

		// I wrote something -> Send it
		if(FD_ISSET(0,&set_of_files_to_be_polled)){
			/* Clear my buffer for encryption */
			memset(input_buffer, '\0', sizeof(input_buffer));
			// Read what I want to sent
			input_bytes = read(0,input_buffer,sizeof(input_buffer));

			if(input_bytes < 0 ){
				perror("Something went wrong with the read!\n");
				exit(1);
			}

			// Encrypt
			if(cipher_encrypt(cryptodev_fd,sess)){
				perror("Something went wrong when encrypting your message!");
			}
			
			// Sent to server
			if(insist_write(socket_fd,input_buffer,sizeof(input_buffer)) != sizeof(input_buffer)){
					perror("Something went wrong when writing to the stdout!");
			}
			// Write again?
			fprintf(stdout,CYAN "Client: " RESET );
			fflush(stdout);
		}

    }

	/* Finish crypto session */
    if (ioctl(cryptodev_fd, CIOCFSESSION, &sess.ses)) {
            perror("ioctl(CIOCFSESSION)");
            return 1;
    }

    if (close(cryptodev_fd) < 0) {
            perror("close(cryptodev_fd)");
            return 1;
    }

    fprintf(stderr, "\nDone.\n");
    return 0;
}
