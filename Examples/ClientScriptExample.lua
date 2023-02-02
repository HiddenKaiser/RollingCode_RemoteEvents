-- Client
local ReplicatedStorage = game:GetService("ReplicatedStorage");
local RemoteParser = require( ReplicatedStorage:WaitForChild("RemoteParser") );

local remote = RemoteParser.new( ReplicatedStorage.Remote );

remote.On("ClientExample"):Connect(function(arg1, arg2)
	print("Client says: ", arg1, arg2);
end)

-- method name is passed in the first argument, so that a developer doesn't have to create and save a variable for every single method.

while true do
	for i = 1,1 do
		remote:FireServer("Test", "arg1", "arg2", "yes")
	end
	remote:FireServer("Method2", "a", "b")
	wait(0.5)
end
