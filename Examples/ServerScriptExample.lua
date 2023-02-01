-- Server
local ReplicatedStorage = game:GetService("ReplicatedStorage");
local RemoteParser = require( ReplicatedStorage:WaitForChild("RemoteParser") );

local parser = RemoteParser.new( ReplicatedStorage.Remote );

local Connection = parser.On("Test", true):Connect(function(player, arg1, arg2, ...)
	warn(player, arg1, arg2, "\nExtra Args: ", ...);
end)

parser.On("Method2", true):Connect(function(player, ...)
	warn(player, "Method 2:", ...);
end)