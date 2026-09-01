# Citadel

## Key value encrypted storage
<br>
This program is meant to be used as a key value vault for secure local password or other short strings. <br>
It is intended to be used with the following flags :  <br>
-e -> marks this operation as an ENCRYPT operation. This is default behavior. (requires a key and a value) <br>
-d -> marks this operation a a DECRYPT operation, just requires a key and you will be prompted for your password to retrieve the value <br>
-vf -> precedes a path string, points to a specific location for your vault file, main reason would be if your vault file is in a non-standard location such as a mounted flash drive. <br>
-k -> precedes the key to the value you are trying to retreive from the vault <br>
-h -> display the help message you are currently reading. <br>
-dk -> delete a key and its associated value from the vault. <br>
-defcon -> precedes an integer (1,2,3,4,5) for an ENCRYPT operation only, specifies where the new entry should go. <br>
-ls -> lists all entries in your vault. <br>
-loglevel -> verbosity/log level, precedes an acceptable value, acceptable values are debug, info, warn, error, critical. Default is error. <br>
-repass -> precedes a DEFCON option, 1 for defcon 1 and so on. Changes the password for that entire section of the vault. You must verify the current password first. <br>
-allkeys -> precedes an integer (1,2,3,4,5) for defcon level, will gather and decrypt every key in that defcon level in one operation <br>
-keylist -> precedes a list of keys , requires the -defcon option to say which level for correctness purposes, decrypts all of the selected keys in that particular defcon level, similar to -allkeys just more constrained. The only valid way to use this is like such citadel -keylist key1 key2 key3 key4 key5 -defcon 5 <br>
<br>
<br>
The argon2 parameters are cranked up or down depending on the defcon level, so be aware defcon1 secrets take a while to encrypt and decrypt. It truly is meant for the most sensitive secrets, otherwise lower levels will be quicker while still retaining an acceptable security profile. <br>
This program has 5 separate levels of the vault: <br>
DEFCON1 -> MOST SERIOUS SECRETS, SHOULD HAVE FEW ENTRIES AND MAXIMALLY COMPLEX PASSWORD <br>
DEFCON2 -> VERY SERIOUS SECRETS, SHOULD ALSO HAVE FEW ENTRIES AND A MAXIMALLY COMPLEX PASSWORD <br>
DEFCON3 -> MID-LEVEL SERIOUS SECRETS, SHOULD HAVE A COMPLEX PASSWORD, COULD BE WRITTEN DOWN ON PAPER <br>
DEFCON4 -> LESS-SERIOUS, ONLINE ACCOUNT PASSWORDS AND THINGS OF THIS NATURE, COULD BE WRITTEN DOWN ON PAPER <br>
DEFCON5 -> LEAST SERIOUS, PASSWORD DOES NOT NEED TO BE VERY COMPLEX JUST ENOUGH TO KEEP LOOKY LOOS OUT, COULD BE WRITTEN DOWN ON PAPER <br>

Values are taken the same way as passwords are, so there will be no bash history concerns.


## Basic Usage Examples

### Create New Entry
citadel -e -k my_github_password -defcon 3

citadel -e -k my_lemmy_password -defcon 3

citadel -e -k codeberg_password -defcon 2

### Decrypt An Entry
citadel -d -k my_github_entry

citadel -d -k my_lemmy_password

### Decrypt Many Entries
citadel -keylist my_github_password my_lemmy_password -defcon 3

### Decrypt All Entries In Vault Level
citadel -allkeys -defcon 3


### Delete A Key And Subsequent Value
citadel -dk -k my_github_password

### Change Vault Section Password
citadel -repass 3 

### List All Vault Keys And Their DEFCON Level
citadel -ls

### Using Log Levels
citadel -loglevel debug -d -k my_lemmy_password

### Seeing The Help Menu
citadel -h

## Base Machine Requirements
As it is written, citadel requires a minimum of 8GB of memory to run it safely and 4 CPU cores. If you do not meet these requirements, you will need to modify the Argon2 parameters in key_derivation.cpp under the crypt directory.
Be aware, if you modify the params, you can only use your custom binary to decrypt any secrets you store with it.