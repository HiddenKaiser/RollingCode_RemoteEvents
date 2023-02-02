-- Server
local ReplicatedStorage = game:GetService("ReplicatedStorage");
local RemoteParser = require( ReplicatedStorage:WaitForChild("RemoteParser") );

local remote = RemoteParser.new( ReplicatedStorage.Remote );

-- remote.On emulates a RbxScriptSignal, so you can use the same methods as you would with a regular event!

-- connection can be saved to a variable
local Connection = remote.On("Test", true):Connect(function(player, arg1, arg2, ...)
	warn(player, arg1, arg2, "\nExtra Args: ", ...);
end)

-- but it doesn't have to be
remote.On("Method2", true):Connect(function(player, ...)
	warn(player, "Method 2:", ...);
end)

-- you can yield on these too!
remote.On("Test"):Wait();

print("First function!");

wait(5);

-- you can also disconnect them just like connections!
Connection:Disconnect();

while true do
	remote:FireAllClients("ClientExample", "hello", "world");
	wait(1);
end
