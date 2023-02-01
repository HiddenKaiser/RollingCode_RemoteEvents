-- Client
local ReplicatedStorage = game:GetService("ReplicatedStorage");
local RemoteParser = require( ReplicatedStorage:WaitForChild("RemoteParser") );

local parser = RemoteParser.new( ReplicatedStorage.Remote );

while true do
	for i = 1,2 do
		parser:FireServer("Test", "arg1", "arg2", "yes")
	end
	parser:FireServer("Method2", "a", "b")
	wait(0.5)
end