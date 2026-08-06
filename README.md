# Citadel

## Key value encrypted storage
<br>
This program is meant to be used as a key value vault for secure local password or other short strings. <br>
It is intended to be used with the following flags :  <br>
-e -> marks this operation as an ENCRYPT operation. This is default behavior. (requires a key and a value) <br>
-d -> marks this operation a a DECRYPT operation, just requires a key and you will be prompted for your password to retrieve the value <br>
-vf -> precedes a path string, points to a specific location for your vault file, main reason would be if your vault file is in a non-standard location such as a mounted flash drive. <br>
-k -> precedes the key to the value you are trying to retreive from the vault <br>
-v -> precedes the value FOR ENCRYPTION OPERATION ONLY. <br>
-h -> display the help message you are currently reading. <br>
-dk -> delete a key and its associated value from the vault. <br>
-defcon -> precedes an integer (1,2,3,4,5) for an ENCRYPT operation only, specifies where the new entry should go. <br>
-ls -> lists all entries in your vault. <br>
-loglevel -> verbosity/log level, precedes an acceptable value, acceptable values are debug, info, warn, error, critical. Default is error. <br>
-repass -> precedes a DEFCON option, DEFCON1 for defcon 1 and so on. Changes the password for that entire section of the vault. You must verify the current password first. <br>
<br>
<br>
The argon2 parameters are cranked up or down depending on the defcon level, so be aware defcon1 secrets take a while to encrypt and decrypt. It truly is meant for the most sensitive secrets, otherwise lower levels will be quicker while still retaining an acceptable security profile. <br>
This program has 5 separate levels of the vault: <br>
DEFCON1 -> MOST SERIOUS SECRETS, SHOULD HAVE FEW ENTRIES AND MAXIMALLY COMPLEX PASSWORD <br>
DEFCON2 -> VERY SERIOUS SECRETS, SHOULD ALSO HAVE FEW ENTRIES AND A MAXIMALLY COMPLEX PASSWORD <br>
DEFCON3 -> MID-LEVEL SERIOUS SECRETS, SHOULD HAVE A COMPLEX PASSWORD, COULD BE WRITTEN DOWN ON PAPER <br>
DEFCON4 -> LESS-SERIOUS, ONLINE ACCOUNT PASSWORDS AND THINGS OF THIS NATURE, COULD BE WRITTEN DOWN ON PAPER <br>
DEFCON5 -> LEAST SERIOUS, PASSWORD DOES NOT NEED TO BE VERY COMPLEX JUST ENOUGH TO KEEP LOOKY LOOS OUT, COULD BE WRITTEN DOWN ON PAPER <br>