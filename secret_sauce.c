#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#pragma warning(disable : 4996)

#define LINE 64						/*Maximum length for every user submitted string*/
#define MIN_HANDLE 5					/*Minimum address/handle is 5 characters*/
#define MIN_MASTER 3					/*Minimum master key is 3 characters long*/
#define MIN_KEY 10					/*Minimum password length is 10 characters*/
#define FILENAME "secret.bin"				/*Binary database is used for added security.*/

/*The central data structure of the program. Passwords are stored in an encrypted state in a binary file as a part of these "secret" structures,
this way the information is harder to access and parse outside this program. The secret structure stores the handle to access the password, encrypted password that
is XOR'ed with the submitted master key, and the length of the password used in deciphering.*/
typedef struct SECRET {					
	char handle[LINE];
	int length;
	char encrypted_key[LINE];
}secret;

int read_input_number();										/*Functions for reading user's input. Several other functions more readale as a result of separating input fetching..*/
int read_input_line(char* buffer, char* prompt);
long int fileSize(FILE* file);

secret make_secret();											/*Creates a secret based on user input for address, password and master key*/
void save_to_binary();											/*Saves the secret structure to a database binary file*/
void cipher(char *secret, int secret_size, char *key, int key_size);	/*The encryption algorithm XOR's the password and master key, and only the encrypted password is stored in the structure/database*/
void unlock_secret();											/*Unlocks a secret by asking for the address/handle and master key, then decrypts the saved encrypted password XOR'ing against the submitted master key. This means that in case the master key is forgotten, the password is not recallable*/
void print_secrets();											/*Prints a list of all saved passwords in the database together with a visual representation of the encrypted password. the encrypted passwords are not printed in plaintext for security reason and because they contain characters that cannot be conventionally printed, like control cahracters*/
void clear_database();											/*Clears the database, removing all entries*/

int main() {
	/*"Secret Sauce" password manager keeps a binary save file of encrypted passwords and addresses/handles.*/
	int choice = 0;
	int help_text = 0;
	char filename[LINE] = { 0 };
	FILE* file = NULL;

	printf("Welcome to \"The Secret Sauce\" password manager.\n");

	fopen_s(&file, FILENAME, "rb");
	if (file == NULL) {			/*If the program can't find the database file, it will print additional information and create an empty one.*/
		fprintf(stderr, "This program helps keep your passwords safe and secure.\nThe program keeps the stored passwords encrypted in the following binary database: %s\nError locating file.\nCreating a new database file....\n", FILENAME);
		fopen_s(&file, FILENAME, "wb");
		if (file == NULL) {
			fprintf(stderr, "Error: couldn't create a save file!\n");
			return 1;
		}
		else {
			printf("New password database %s created succesfully!\n", FILENAME);
		}
	}
	fclose(file);

	//Asks user what function to run, will return to the choice after the function is run, program ends when user inputs 6
	while (choice != 6) {
		if (help_text == 0) {												//Prints the "manual" when program first runs and when user asks for help menu
			printf("\nThe choices are:\n1: Store a password by site/address\n2: Unlock a stored password of a site/address with master key\n3: Print a report of sites and encrypted passwords\n4: Clear the database\n5: Help\n6: Exit program\n");
			help_text++;
		}
		else if (choice != 0) {
			printf("What would you like to do? Press 1-6. Help: 5\n");
		}
		choice = read_input_number();
		switch (choice) {													//Switch manages what function to run based on user input, which makes the main()-program really simple
		case 1:
			save_to_binary();
			break;
		case 2:
			unlock_secret();
			break;
		case 3:
			print_secrets();
			break;
		case 4:
			clear_database();
			break;
		case 5:
			help_text = 0;
			break;
		case 6:
			printf("\nPlease note that in case you forget your master key, the stored passwords cannot be recalled.\nThe program ends...\n");
			break;
		}
	}
	return 0;										//Program ends when user inputs 6 and the while-loop ends
}

int read_input_number() {							/*This function is only called to read the user's choice for the program to do, hence it only accepts numbers from 1 to 6*/
	char input[LINE] = { 0 };
	int number = 0;

	while (number < 1 || number > 6) {
		fgets(input, LINE, stdin);					/*Instead of fgets reading a buffer/line of text from stdin, this could be optimized to only read a single integer using fgetc(), this method is more flexible
													larger numbers, but since only 1-6 is accepted anyhow, the added flexibility is not used by this program.*/
		input[strcspn(input, "\n")] = 0;
		if (input == NULL) {
			fprintf(stderr, "Error reading user input.\n");
		}
		else {
			number = (int)strtol(input, NULL, 0);
			if (number < 0 || number > 6) {
				printf("Please enter a number from 1 to 6.\n");
			}
		}
	}
	return number;
}

int read_input_line(char* line, char* prompt) {		/*A simple function to read a line of text with the added prompt to print, only the most basic error checking performed here, further parsing and checking is performed on the calling functions*/
	printf("%s", prompt);
	fgets(line, LINE, stdin);
	if (line == NULL) {
		fprintf(stderr, "Error reading input.\n");
		return 0;
	}
	else {
		line[strcspn(line, "\n")] = 0;				/*Remove newline that fgets places at the end of the input*/
		return 1;
	}
}

void save_to_binary()
{
	/*Saving an entry to the binary database is performed by creating the entry first with the make-secret -function call and then, if it's not an empty structure, appending it in binary mode to the file.*/
	FILE* file = NULL;
	secret secret_to_add = { 0 };
	secret_to_add = make_secret();

	if (secret_to_add.length > 0) {							/*As make-secret performs a check to see if an entry with the same handle already exists, it can return an empty secret. In this case the entry won't be saved.*/
		fopen_s(&file, FILENAME, "ab");
		if (file != NULL) {
			fwrite(&secret_to_add, sizeof(secret), 1, file);
			printf("The password has been saved into save file in binary format.\n");
			fclose(file);
		}
		else {
			fprintf(stderr, "Error opening the save file for writing.\n");
		}
	}
	return;
}

secret make_secret()
{
	/*This function performs quite a bit user-input validating and parsing, which in hindsight could be it's separate function. There are three user submitted variables that are used in creating a secret structure:
	#1 handle, #2 password and #3 master key, the password is not actually saved anywhere, but encrypted with the Cipher-function and the encrypted data saved in the structure that will be saved to the binary database*/
	FILE* file;
	secret passwd = { 0 }, empty_s = { 0 };
	char handle[LINE] = { 0 };
	char secret_key[LINE] = { 0 };
	char master_key[LINE] = { 0 };
	int success = 0, handle_size = 0, m_key_size = 0, s_key_size = 0, secrets = 0, match = 0;

	printf("\nIn order to store a password to the save file, you need to submit an address/site or other handle that is at minimum %d characters long,\npassword that is at minimum %d characters long and the master key used in encryption.\n\nPlease note that in the event you forget your master key the password cannot be recalled.\nMaximum input length is %d characters. Letters, numbers and most common symbols (question marks, exclamation marks, dots, asterix, plus, minus parenthesis etc.) are allowed. White space and special characters such as '¤' is not allowed.\n\n",MIN_HANDLE, MIN_KEY, LINE);

	do {
		success = read_input_line(handle, "Enter the address/handle:\n");
		handle_size = strlen(handle);
		for (int i = 0; i < handle_size; i++) {
			if (isspace(handle[i]) && success != 0) {
				printf("No white space allowed!\n");
				success = 0;
			}
		}
		if (handle_size < MIN_HANDLE) {
			printf("The minimum length is %d characters\n", MIN_HANDLE);
			success = 0;
		}
		else {
			fopen_s(&file, FILENAME, "rb");							/*Opens the file to check that user submitted handle is not already present in another entry*/
			if (file == NULL) {
				fprintf(stderr, "Error opening save file %s to check redundancy.\n", FILENAME);
				return empty_s;
			}
			else {
				secrets = fileSize(file) / (int)sizeof(secret);
				for (int i = 0; i < secrets; i++) {
					fseek(file, (sizeof(secret) * i), SEEK_SET);
					secret redundancy_check = { 0 };
					fread(&redundancy_check, sizeof(secret), 1, file);
					if (strncmp(redundancy_check.handle, handle, LINE) == 0) {
						match++;
					}
				}
				fclose(file);
			}
			if (match == 0) {										/*If a match is not found, places the submitted handle into the new entry*/
				strncpy(passwd.handle, handle, handle_size);
			}
			else {													/*If a match has been found, print a message prompting so, and return a zeroed dummy secret, that will not be saved to the file*/
				printf("There is already a password for the address/handle: %s saved in the file.\n If you can't remember the master key, you can clear the database and save it again.", handle);
				return empty_s;
			}
		}
	} while (success == 0);
	success = 0;
	do {
		success = read_input_line(master_key, "Enter the master key:\n");
		m_key_size = strlen(master_key);
		for (int i = 0; i < m_key_size; i++) {
			if (isspace(master_key[i])) {
				printf("No white space allowed!\n");
				success = 0;
			}
		}
		if (m_key_size < MIN_MASTER) {
			fprintf(stderr,"The minimum length is %d characters.\n", MIN_MASTER);
			success = 0;
		}
		if (m_key_size > LINE) {
			fprintf(stderr, "The maximum character limit is %d characters.", LINE);
			success = 0;
		}
		
	} while (success == 0);
	success = 0;

	do {
		success = read_input_line(secret_key, "Enter the password to encrypt:\n");
		s_key_size = strlen(secret_key);
		for (int i = 0; i < s_key_size; i++) {
			if (isspace(secret_key[i]) && success != 0) {
				printf("No white space allowed!\n");
				success = 0;
			}
		}
		if (s_key_size < MIN_KEY) {
			printf("The minimum length is %d characters.\n", MIN_KEY);
			success = 0;
		}
		if (s_key_size > LINE) {
			fprintf(stderr, "The maximum character limit is %d characters.", LINE);
			success = 0;
		}
	} while (success == 0);
	passwd.length = s_key_size;
	cipher(secret_key, s_key_size, master_key, m_key_size);
	strncpy(passwd.encrypted_key, secret_key, s_key_size);
	memset(secret_key, 0, s_key_size);								/*Clear the buffers that were holding sensitive data.*/
	memset(master_key, 0, m_key_size);

	return passwd;													/*Only the encrypted password is leaving this function as a part of a structure*/
}

void cipher(char *secret,int secret_size, char *key, int key_size)
{
	/*This is the encryption "algorithm": XOR two strings with each other, with the other repeating for the duration of the other.
	Additional security is achieved by saving predefined structures in a binary file, so the information in the file is hard to parse outside of this program.*/
	for (int k = 0; k < secret_size; k++) {
		int n = 0;
		if (n < key_size) {											/*Master key's looping variable n can't exceed it's length, so it will begin from the start (n = n - key_size) when it would exceed it's size*/
			secret[k] = secret[k] ^ key[n];
			n++;
		}
		else {
			n = n - key_size;
			secret[k] = secret[k] ^ key[n];
			n++;
		}
	}
	return;
}

long int fileSize(FILE* file) {											/*This simple filesize function is used when calculating how many passwords are stored in the save file*/
	long size = 0;
	fseek(file, 0L, SEEK_END);
	size = ftell(file);
	rewind(file);
	return size;
}

void unlock_secret() {													/*Unlock a secret by fetching an entry with matching handle and run cipher algorithm with the submitted master key, code could be further simplified by removing the user input parsing and error checking into separate functions*/
	FILE* file = NULL;
	char handle[LINE] = { 0 }, m_key[LINE] = { 0 }, s_key[LINE] = { 0 };
	int secrets = 0, success = 0, size = 0, s_key_size = 0, m_key_size = 0, match = 0;
	secret empty = { 0,0,0 };

	fopen_s(&file, FILENAME, "rb");
	if (file == NULL) {
		fprintf(stderr, "Error opening file %s.\n", FILENAME);
		return;
	}
	else {
		do {
			success = read_input_line(handle, "Enter the address/handle of the password you wish to unlock:\n");
			size = strlen(handle);
			for (int i = 0; i < size; i++) {
				if (isspace(handle[i]) && success != 0) {
					printf("No white space allowed!\n");
					success = 0;
				}
			}
			if (size < MIN_HANDLE) {
				printf("The minimum length is %d characters\n", MIN_HANDLE);
				success = 0;
			}
		} while (success == 0);
		success = 0;
		size = 0;
		secrets = fileSize(file) / (int)sizeof(secret);
		for (int i = 0; i < secrets; i++) {
			fseek(file, (sizeof(secret) * i), SEEK_SET);
			secret candidate = { 0 };
			fread(&candidate, sizeof(secret), 1, file);
			if (strncmp(candidate.handle, handle, LINE) == 0) {				/*Compare every stored secret with the user submitted handle, if more than one is found then the latest entry will be processed.*/
				strncpy(s_key, candidate.encrypted_key, candidate.length);
				s_key_size = candidate.length;
				match++;
			}
			candidate = empty;
		}
		fclose(file);
		if (match == 0) {
			printf("Couldn't locate a saved password for the submitted address. Check the spelling.\n");
		}
		else if (match > 0) {
			if (match > 1) {	/*This is a remnant from an earlier version when the program didn't perform a redundancy check when creating a new entry. Shouldn't be possible to get more than one match now, but it's here just in case binary file is being modified elsewhere (?)*/
				printf("Found more than one match for the address submitted.\nWill process the latest entry...\n");
			}
			if (match == 1) {
				printf("Found a match!\n");
			}
			do {
				success = read_input_line(m_key, "Enter the master key used encrypting the password:\n");
				size = strlen(m_key);
				for (int i = 0; i < size; i++) {
					if (isspace(m_key[i]) && success != 0) {
						printf("No white space allowed!\n");
						success = 0;
					}
				}
				if (size < MIN_MASTER) {
					printf("The minimum length is %d characters\n", MIN_MASTER);
					success = 0;
				}
				if (size > LINE) {
					fprintf(stderr, "The maximum character limit is %d characters.", LINE);
					success = 0;
				}
				m_key_size = size;
			} while (success == 0);

			printf("Decrypting the password...\n");
			cipher(s_key, s_key_size, m_key, m_key_size);
			printf("The password is: %s\n", s_key);

			memset(s_key, 0, s_key_size);									/*After printing the decrypted password, clear the buffers that contained all relevant information and zero the int variables*/
			memset(m_key, 0, m_key_size);	
			s_key_size = 0;
			m_key_size = 0;
		}
		return;
	}
}

void print_secrets(){
	FILE* file = NULL;
	int secret_amount = 0;
	char* header_one = "ADDRESS/HANDLE:";									/*Headers for formatting the output*/
	char* header_two = "ENCRYPTED KEY:";

	fopen_s(&file, FILENAME, "rb");
	if (file == NULL) {
		fprintf(stderr, "Error opening the save file %s.\n", FILENAME);
		return;
	}
	else {
		printf("This is a list of every encrypted password and their respective handle or address.\nTo unlock a specific key, select the second function from the main menu (press 2).\n\n");
		secret_amount = fileSize(file) / (int)sizeof(secret);
		printf("%4s%-64s%s\n","", header_one, header_two);					/*With this formatting, the headers match the text fields that contain the data below.*/
		for (int i = 0; i < secret_amount; i++) {
			fseek(file, (sizeof(secret) * i), SEEK_SET);
			secret printable_secret = { 0 };
			fread(&printable_secret, sizeof(secret), 1, file);
			printf("#%d: %-63s ",i + 1, printable_secret.handle);
			for (int i = 0; i < printable_secret.length; i++) {
				printf("$");												/*Because the encrypted passwords contain characters that can't be conventionally printed, such as ASCII 0-32 & 255 and contain
																			very little meaningful information for the user, while posing a slight security risk, the program instead uses a simpler and more secure approach of printing $$$-for the length of the saved password.*/
			}
			printf("\n");
		}
		fclose(file);
	}
	return;
}

void clear_database() {														/*Database is cleared by opening the file in wb-mode, without actually writing anything.*/
	FILE* file = NULL;
	char answer = 'a';
	printf("This will clear all saved entries in the save file.\n");
	do {
		printf("Are you sure? Press \"y\" to continue, \"n\" to stop.");	/*Additional check is performed, so the database will not get cleared by accidentaly pressing the number 4.*/
		answer = getc(stdin);
	} while (answer != 'y' && answer != 'n');
	if (answer == 'y') {
		fopen_s(&file, FILENAME, "wb");
		if (file == NULL) {
			fprintf(stderr, "Error accessing the file %s.\n", FILENAME);
		}
		else {
			printf("The save file has been cleared of contents.\n");
			fclose(file);
		}
	}
	else {
		printf("The save file hasn't been cleared. Returning to menu.\n");
	}
	return;
}
