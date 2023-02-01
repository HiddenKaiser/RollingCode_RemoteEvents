--[[
> RemoteParser.lua
 >> ScriptEvents.lua
--]]


-- !!! NOTE FROM CREATOR
-- This code was created back in 2020-2021 and is not fully representative of my current coding practice
-- for example, type checking is not included here


-- This wrapper class is designed to use something similar to rolling code to help secure all remotes.
-- This small amount of protection would help to stop 99% of exploiters attempting this.
-- This also allows for multiple events on a singular remote object, which many games use

--// Configuration
local GLOBAL_CONFIG = {
	debug_mode = true;
	extra_key = 7; -- if your security gets decompiled, just change the extra key it will probably break the new exploits
}

--// Services

local HttpService = game:GetService("HttpService");
local RunService =  game:GetService("RunService");
local Debris = game:GetService("Debris");

--// Internal

local ScriptEvents = require(script:WaitForChild("ScriptEvents"));

local IsServer = RunService:IsServer();
local IsStudio = RunService:IsStudio();

local ParsedRemotes = {};


--// Utility

local function Print(...)
	return GLOBAL_CONFIG.debug_mode and print(...);
end

local function Warn(...)
	return GLOBAL_CONFIG.debug_mode and warn(...);
end

-- convert text into a combined number
local function bit(str)
	local numbers, final = {str:byte(1,-1)}, 0;
	for _,s in ipairs(numbers) do
		local n = tonumber(s);
		final += n or "";
	end
	return (final or 0);
end


-- check if calling script has elevated permissions, aka check if an exploiter is trying to read this script
-- returns false if the player is trying to exploit this script
local function CheckEnv()
	if IsStudio then
		return true;
	end
	
	local src, did_run, run_success, ErrorCode
	
	run_success, ErrorCode = pcall(function()
		src = Instance.new("LocalScript");
		src.Source = ("print('im exploiting')");
		did_run = true;
	end)
	
	if did_run or run_success then
		-- required by an exploit
		Warn("Called by an exploit!");
		return false;
	end
	
	return true;
end



--// Main Parser

local RemoteParser = {};
RemoteParser.__index = RemoteParser;


function RemoteParser.new(RemoteEvent: Instance, Settings)
	
	if ParsedRemotes[RemoteEvent] then
		return ParsedRemotes[RemoteEvent];
	end
	
	Print("Creating new remote parser for '"..RemoteEvent.Name.."'");
	
	local Settings = Settings or {}
	
	local self = {
		RemoteEvent = RemoteEvent;
		Settings = Settings;
		Methods = {};
		Connections = {};
		
		Calls = 0;
		
		IsServer = IsServer;
		Created = tick();
	}
	
	setmetatable(self, RemoteParser);
	
	self.On = function(...) -- wrap_data puts all arguments into a table
		return self:_hookMethod(...);
	end
	
	if self.IsServer then
		--// Server
		
		table.insert(self.Connections, RemoteEvent.OnServerEvent:Connect(function(Player, Method, Arguments, ClientAuthData)
			
			local _method = self:_findMethod(Method);
			if not _method then
				return (Print("Couldnt find method:", Method) and nil);
			end;
			
			self.Calls += 1;
			
			if _method.secure then
				
				local Given = ClientAuthData and ClientAuthData.NextAuth
				
				if not Given then  return Warn(Player.Name, "did not include auth data, event requires auth data");  end
				if type(Given) == "string" then  Given = Given:byte();  end
				
				local ServerData = self:GetAuthData(Method, Player);
				local Expected = ServerData and ServerData.NextAuth;
				local Calls = ServerData and ServerData.Calls;
				
				if Given ~= Expected then
					return Warn(Player.Name, "failed auth check, Expected:", Expected, " Got:", Given); 
				end
				if Calls and self.Calls > Calls then
					return Warn(Player.Name, "Too many calls recieved, 3rd party tampering expected.");
				end
				
			end
			
			local Final = {}
			if not _method.wrap_data and type(Arguments) == "table" then
				for i, argument in pairs(Arguments) do
					Final[i] = argument;
				end
			else
				Final[1] = Arguments
			end
			
			return _method:Invoke( Player, unpack(Final) );
		end));
		
	else
		--// Client
		
		table.insert(self.Connections, RemoteEvent.OnClientEvent:Connect(function(Method, Arguments)
			local _method = self:_findMethod(Method);
			if not _method then return end
			
			local Final = {}
			if not _method.wrap_data and type(Arguments) == "table" then
				for i, argument in pairs(Arguments) do
					Final[i] = argument;
				end
			else
				Final[1] = Arguments
			end
			
			return _method:Invoke( unpack(Final) );
		end));
		
	end
	
	ParsedRemotes[RemoteEvent] = self;
	
	return self;
end


function RemoteParser:FireServer(Method, ...)
	assert(not self.IsServer and CheckEnv(), ":FireServer() can only be called from the Client");
	self.Calls += 1;
	return self.RemoteEvent:FireServer( Method, {...}, self:GetAuthData(Method) );
end

function RemoteParser:FireClient(Player, Method, ...)
	assert(self.IsServer, ":FireClient() can only be called from the Server");
	return self.RemoteEvent:FireClient( Player, Method, {...} );
end

function RemoteParser:FireAllClients(Player, Method, ...)
	assert(self.IsServer, ":FireAllClients() can only be called from the Server");
	return self.RemoteEvent:FireAllClients( Method, {...} );
end


function RemoteParser:GenerateSeed(Method)
	local jobId = game.JobId;
	jobId = (jobId ~= "" and jobId) or "00000000-0000-0000-0000-000000000000"
	
	return ( bit(Method) + bit(jobId) ) * GLOBAL_CONFIG.extra_key;
end

function RemoteParser:GetAuthData(Method, Player)
	local _method = Method and self:_getMethod(Method);
	if not _method then  return {}  end;
	
	local Data = {}
	
	if (not self.IsServer) then
		--// Client
		Data.NextAuth = ("").char( _method.auth:NextInteger(1,100) );
	elseif Player then
		--// Server
		local auth = _method.auth[Player] or Random.new(_method.seed);
		Data.NextAuth = auth:NextInteger(1,100);
		_method.auth[Player] = auth;
	end
	
	return Data;
end


function RemoteParser:_hookMethod(Method, secure, wrap_data, extra_settings)
	assert(Method, "Must Pass Method Name");
	
	local _method = self:_getMethod(Method);
	
	_method.secure = secure;
	_method.wrap_data = wrap_data;
	_method.config = (type(extra_settings) == "table" and extra_settings) or {};
	
	return (_method and _method.Invoked);
end


function RemoteParser:_getMethod(Method)
	local _method = self.Methods[Method]
	
	if not _method then
		_method = ScriptEvents.new();
		
		_method.name = Method;
		_method.seed = self:GenerateSeed(Method);
		_method.auth = (self.IsServer and {}) or Random.new(_method.seed);
		
		self.Methods[Method] = _method;
	end
	
	return _method;
end

function RemoteParser:_findMethod(Method)
	local _method = self.Methods[Method];
	
	if not _method and (not self.expired) and self.Created then
		
		-- wait to see if it can find the method ASAP
		if (tick() - self.Created) <= 1  then
			repeat
				RunService.Heartbeat:Wait();
				_method = self.Methods[Method];
			until _method or (tick() - self.Created) > 1
		else
			self.expired = true;
		end
		
	end
	
	return _method;
end


function RemoteParser:Destroy()
	for i,v in pairs(self.Connections) do
		v:Disconnect(); v = nil;
		self.Connections[i] = nil;
	end
	
	local function empty(t)
		for i,v in pairs(t) do
			if type(v) == "table" then
				t[i] = empty(v);
			else
				t[i] = nil;
			end
		end
		return t
	end
	
	empty(self);
end

return RemoteParser;