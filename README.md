# Citadel

## Key value encrypted storage

This program is meant to be used as a key value vault for secure local password or other short strings.
It is intended to be used with the following flags : 
-e -> marks this operation as an ENCRYPT operation. This is default behavior. (requires a key and a value)
-d -> marks this operation a a DECRYPT operation, just requires a key and you will be prompted for your password to retrieve the value
-vf -> precedes a path string, points to a specific location for your vault file, main reason would be if your vault file is in a non-standard location such as a mounted flash drive
-k -> precedes the key to the value you are trying to retreive from the vault
-v -> precedes the value FOR ENCRYPTION OPERATION ONLY.
-h -> display the help message you are currently reading.
-dk -> delete a key and its associated value from the vault
-defcon -> precedes an integer (1,2,3,4,5) for an ENCRYPT operation only, specifies where the new entry should go
-ls -> lists all entries in your vault
-loglevel -> verbosity/log level, precedes an acceptable value, acceptable values are debug, info, warn, error, critical. Default is error.
-repass -> precedes a DEFCON option, DEFCON1 for defcon 1 and so on. Changes the password for that entire section of the vault. You must verify the current password first.

This program has 5 separate levels of the vault:
DEFCON1 -> MOST SERIOUS SECRETS, SHOULD HAVE FEW ENTRIES AND MAXIMALLY COMPLEX PASSWORD
DEFCON2 -> VERY SERIOUS SECRETS, SHOULD ALSO HAVE FEW ENTRIES AND A MAXIMALLY COMPLEX PASSWORD
DEFCON3 -> MID-LEVEL SERIOUS SECRETS, SHOULD HAVE A COMPLEX PASSWORD, COULD BE WRITTEN DOWN ON PAPER
DEFCON4 -> LESS-SERIOUS, ONLINE ACCOUNT PASSWORDS AND THINGS OF THIS NATURE, COULD BE WRITTEN DOWN ON PAPER
DEFCON5 -> LEAST SERIOUS, PASSWORD DOES NOT NEED TO BE VERY COMPLEX JUST ENOUGH TO KEEP LOOKY LOOS OUT, COULD BE WRITTEN DOWN ON PAPER