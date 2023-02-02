!!! NOTE FROM CREATOR !!!

- This code was created back in 2020-2021 and is not fully representative of my current coding practice. 
For example, type checking is not included here


- This wrapper class is designed to use something similar to rolling code to help secure all remotes. This small amount of protection would help to stop 99% of exploiters attempting this. This also allows for multiple events on a singular remote object, which many games use

README taken from RemoteParser.lua comments


-------------------------------------------------------------------------

This code was meant to be only seen abstractly so it's readability is bad.
Hence, i'll explain what the main code does:


- First, It creates a wrapper for the remote which can create methods

- Each method has settings and data along with it.

- For each player, it saves a seeded random and every time the remote is called it advances to the next integer. It also saves how much that method has been called by that player.

- If someone tries to call the method from outside the module, and the method is set as secured (meaning it should only be getting called through the module), the method will be seen as invalid, and wont trigger the .On event.

- Aditionally, if someone tries to spoof the verification system, the codes will become mismatched between the server and the client and the server will start to ignore that client's requests.

- It also detects if an exploiter is trying to use the module, because exploits have power which isnt normally allowed by regular roblox scripts. Therefore, it will not allow an exploiter to hijack the module.
