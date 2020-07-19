# PrjRem
Project Remembrance - Personal password utility

Generate strong passwords and store them in an encrypted file. My preference is to have passwords saved somewhere central and anonymous. Most browsers have this capability these days but I find this program still has an use-case for certain things.

A reboot of a previous PrjRem. The focus before was on using true randomness for passwords and storing them encrypted locally. Now the intent is to use good solid principles and tested libraries to make what is a simple program as robust as possible. Python is cross platform, this should be too. File reading and encryption is pretty ordinary computer science stuff, no need to reinvent the wheel.

## Future

#### Remote storage

Password services offer storage you can reach anywhere. I want the option to use SSH for storing on other personal machines as a start

#### Fancy user interface

Program is set up as command based right now. Should be easy to build an UI with one of those cool kids' frameworks.