
/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
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
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include "socket-common.h"
#include <crypto/cryptodev.h>


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
	}	return 0;
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

int main(void)
{	
	/* ========== PARAMETERS ========== */
	char addrstr[INET_ADDRSTRLEN];
	int socket_fd, client_fd,polling,cryptodev_fd;
	ssize_t input_bytes;
	socklen_t len;
	struct sockaddr_in sa;
	fd_set set_of_files_to_be_polled;
	struct session_op sess;

	/* Make sure a broken connection doesn't kill us 
	 *
	 * Sigpipe gets triggered whenever a write fails.
	 * With this command we ensure that sigpipe signal 
	 * is ignored.
	 */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel 
	 * SOCK_STREAM->Tcp connection used to make sure all
	 * messages are sent succesfully
	 * PF_INET->Same as AF_Inet (could be replaced)
	 */
	if ((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Something went wrong when creating the socket!");
		exit(1);
	}
	fprintf(stderr, "TCP Socket created succesfully\n");

	/* Bind to a well-known port 
	 * Memeset clears space of `sa`
	 * ipv4 protocol is defined
	 * port 35001 used as sin port (in socket-common.h)
	 * s_addr set to local_host 
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	/* Socket_fd is bound to 127.0.0.1
	 * and into the NOT well_known port(35001)
	 */
	if (bind(socket_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("Something went wrong when binding the socket!");
		exit(1);
	}
	fprintf(stderr, "Succesfully bound TCP socket to port %d!\n", TCP_PORT);
	fflush(stderr);


	/* Listen for incoming connections 
	 * TCP_BACKLOG defines the length by which 
	 * the queue of pending connections may grow 
	 * in this case TCP_BACKLOG is set to 5
	 * (in socket_common.h)*/
	if (listen(socket_fd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}


	/* Loop forever, accept()ing connections */
	for (;;) {
		//OPEN DAT FILE 
		cryptodev_fd = open("/dev/crypto", O_RDWR);
		if (cryptodev_fd < 0) {
			perror("open(/dev/crypto)");
			return 1;
		}
		//prepare to make a session
		memset(&sess, 0, sizeof(sess));

		// Get crypto session for AES128
		// Init session parameters
		sess.cipher = CRYPTO_AES_CBC;
		sess.keylen = KEY_SIZE;			// socket-common.h
		sess.key    = key;
	
		// Session creation
		if (ioctl(cryptodev_fd, CIOCGSESSION, &sess)) {
			perror("ioctl(CIOCGSESSION)");
			return 1;
		}
		fprintf(stderr, "Waiting for an incoming connection...\n");
		fflush(stderr);

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((client_fd = accept(socket_fd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}

		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}

		fprintf(stderr, "Incoming connection from %s:%d\n",addrstr, ntohs(sa.sin_port));
		fflush(stderr);

		/* Prepare set */
		FD_ZERO(&set_of_files_to_be_polled);

		fprintf(stdout, CYAN "Server: " RESET );
		fflush(stdout);

		/* We break out of the loop when the remote peer goes away */
		for (;;) {

			/* Monitor my input and his output */
			FD_SET(client_fd,&set_of_files_to_be_polled);
			FD_SET(0,&set_of_files_to_be_polled);

			/* Begin monitoring file descriptors */
			polling = select(client_fd+1,&set_of_files_to_be_polled,NULL,NULL,NULL);

			/* polling fails */
			if((polling == -1)){
				fprintf(stdout,"Error in select!");
				fflush(stdout);
				exit(1);
			}

			/* Client said something? */
			if(FD_ISSET(client_fd,&set_of_files_to_be_polled)){

				// Read from client
				input_bytes = read(client_fd,input_buffer,sizeof(input_buffer));

				// Something went wrong || client left
				if (input_bytes <= 0) {
					// Something went wrong
					if (input_bytes < 0)
						perror("read from remote peer failed");
					// Client left: he sent zero bytes
					else
						fprintf(stderr, "\nAlice went away\n");
					// Anyway: leave client
					break;
				}

				fprintf(stdout,"\nClient: ");
				fflush(stdout);

				/* Decrypt client's message */
				if(cipher_decrypt(cryptodev_fd,sess) != 0){
					perror("\nSomething went wrong when decrypting your message!");
				}
				/* Write it in my stdout */
				if(insist_write(1,input_buffer,input_bytes) != input_bytes){
						perror("Something went wrong when writing to the stdout!");
				}

				//prepare to write again
				fprintf(stdout, CYAN "Server: " RESET );
				fflush(stdout);
			}


			/* Im writing something */
			if(FD_ISSET(0,&set_of_files_to_be_polled)){
				/* Clear my buffer for encryption */
				memset(input_buffer, '\0', sizeof(input_buffer));
				// Read what I want to send
				input_bytes = read(0,input_buffer,sizeof(input_buffer));

				if(input_bytes < 0 ){
					perror("Something went wrong with the read!\n");
					exit(1);
				}

				// Encrypt
				if(cipher_encrypt(cryptodev_fd,sess)){
					perror("Something went wrong when encrypting your message!");
				}
				
				// Send to client
				if(insist_write(client_fd,input_buffer,sizeof(input_buffer)) != sizeof(input_buffer)){
						perror("Something went wrong when writing to the stdout!");
				}
				fprintf(stdout, CYAN "Server: " RESET );
				fflush(stdout);
			}
		}

		/* Finish crypto session */
       	if (ioctl(cryptodev_fd, CIOCFSESSION, &sess.ses)) {
        	perror("ioctl(CIOCFSESSION)");
            return 1;
    	}
    	/* Close `file` */
        if (close(cryptodev_fd) < 0) {
            perror("close(cfd)");
			return 1;
    	}

    /* Make sure we don't leak open files */
    if (close(client_fd) < 0){
        	perror("close");
		
		}
	}

	/* This will never happen */
	return 1;
}

