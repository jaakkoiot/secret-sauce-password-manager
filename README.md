# “The Secret Sauce” Password manager
Pure C project for implementing and accessing a secure password storage medium in a binary data file using the command line as an interface.

This is a program that helps users manage passwords in a secure format. The program
keeps saved entries in a binary save file “secret.bin”, located at the directory of the program
and created at the first instance of the program. Passwords are embedded inside structures
“secrets”, and are only stored in an encrypted format. Encryption is performed by bitwise XOR operation of the
submitted password and master key.

The passwords are only recallable if the user remembers the master key used while
encrypting them. In the case the key is lost, the passwords are also lost, as there is no
contingency functionality such as secret questions.

  - Included is the source code (C_Project.c -file). It's the only file required to run the
  program.

  - The first time the program is run, if it doesn't find a save file (password database
  binary file "secret.bin"), it will create a new file to the directory of the program. As the
  program creates a new database if it doesn't find an existing one, I won't include the
  file here.
  
  - User input 1-6 selects the functionality. User input 5 prints the help screen.
  
  The choices are:
  - #1 create a new entry
  - #2 unlock a specific password with the submitted address/handle and master key
  - #3 print a summary of every saved entry in the database file (note: encrypted asswords are only shown as $$$$, because they contain characters that
       can’t be conventionally printed, such as ASCII 0-31 & 127).
  - #4 clear the save file, removing all entries
  - #5 Print help menu, that is also visible the first time the program runs
  - #6 end program
