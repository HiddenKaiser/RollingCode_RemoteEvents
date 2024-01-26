-- !!! NOTE FROM CREATOR
-- This code was created back in 2020-2021 and is not fully representative of my current coding practice
-- for example, type checking is not included here


-- This wrapper class is designed to use something similar to rolling code to help secure all remotes.
-- This small amount of protection would help to stop 99% of exploiters attempting this.

--[[
USAGE

First, make the parser for the specific remote you want to parse.
> local remote = RemoteParser.new( game.ReplicatedStorage.RemoteEvent )

Then, implement your methods using the .On function
>[
remote.On("BuyShop"):Connect(function(Player, wantedItem)
	print(Player.Name, "wants", wantedItem)
end)
]<

RemoteParser.On has 2 option parameters, SecureMethod: boolean and WrapData: boolean

SecureMethod will use the previously described rolling code technique to help secure remotes efficiently.
WrapData will wrap all arguments in a table. Ex: > remote.On("Method1", false, true):Connect(function( Player, arguments: {any} )

>[
local doSecureMethod = true
local wrapData = true
remote.On("MethodName", doSecureMethod, wrapData):Connect(print)
]<

remote.On works both on the server and client

--]]

export type _InternalConfig = {
	secure: boolean?,
	wrap_data: boolean?,
	callBufferSize: number? -- how many calls to cache in order to account for packet loss / mismatched ordering
}

type AuthData = {[Player]: {
	Random: Random?,
	NextAuth: number | string?,
	Calls: number,
	CallHistory: {[number]: number}}
} | Random?

export type Method = {
	name: string,
	seed: number,
	auth: AuthData,
	calls: number,
	config: _InternalConfig?,
	Invoked: any
}

--// Configuration
local GLOBAL_CONFIG = {
	debug_mode = true,
	debug_header = "[RemoteParser]",

	extra_key = 7,  -- if your security gets decompiled and bypassed, change this key and it should mess up various exploits
	method_creation_timeout = 2.5,  -- how long to wait for a method to be created after initilization before giving up
	default_call_buffer_size = 10 -- how many calls to cache in order to account for packet loss / mismatched ordering
}

--// Services

local RunService =  game:GetService("RunService")
local Players = game:GetService("Players")

--// Internal

local ScriptEvents = require( script:WaitForChild("ScriptEvents") ) -- RbxScriptSignal Emulator

local IsServer = RunService:IsServer()
local IsStudio = RunService:IsStudio()

local ParsedRemotes = {}


--// Utility

local function Print(...)
	return GLOBAL_CONFIG.debug_mode and print(GLOBAL_CONFIG.debug_header, ...)
end

local function Warn(...)
	return GLOBAL_CONFIG.debug_mode and warn(GLOBAL_CONFIG.debug_header, ...)
end

-- convert text into a combined number
local function bit(str: string): number
	local numbers, final = { str:byte(1,-1) }, 0
	for _, s in ipairs(numbers) do
		local n: number = tonumber(s)
		final += (n or "")
	end
	return (final or 0)
end


-- check if calling script has elevated permissions, aka check if an exploiter is trying to read this script
-- returns false if the player is trying to exploit this script
local function CheckEnv(): boolean
	if IsStudio then
		return true
	end

	local did_run, run_success

	run_success = pcall(function()
		game:GetService("CoreGui"):FindFirstChild("secure_function") -- should not be able to pass security check
		did_run = true
	end)

	-- if that code ran correctly then the module is running with elevated permissions = Exploiting
	if did_run or run_success then
		-- required by an exploit
		return false
	end

	return true
end



--// Main Parser

local RemoteParser   = {}
RemoteParser.__index = RemoteParser


function RemoteParser.new(RemoteEvent: Instance)

	if ParsedRemotes[RemoteEvent] then
		return ParsedRemotes[RemoteEvent]
	end

	Print("Creating new remote parser for '"..RemoteEvent.Name.."'")

	local self = setmetatable({
		RemoteEvent = RemoteEvent,
		Methods = {},
		Connections = {},

		TotalCalls = 0,

		IsServer = IsServer,
		Created = tick(),

		_internalEvents = ScriptEvents.new()
	}, RemoteParser)

	self.On = function(...)
		return self:_hookMethod(...)
	end
	self.on = self.On -- alias to save some frustration

	if self.IsServer then
		--// Server

		table.insert(self.Connections, RemoteEvent.OnServerEvent:Connect(function(Player, MethodName, Arguments, ClientAuthData)

			if MethodName == "__REQ_METHOD_CREATION_EVENT" then
				local keys, i = table.create(#self.Methods), 1
				for methodName, _ in self.Methods do
					keys[i] = methodName
					i += 1
				end

				return self.RemoteEvent:FireClient(Player, "__METHOD_CREATION_EVENT", keys)
			end

			local _method: Method? = self:_findMethod(MethodName)
			if not _method then
				return Print("Couldnt find method:", MethodName)
			end

			-- perform recall

			self.TotalCalls += 1
			

			if _method.config.secure then
				
				ClientAuthData = typeof(ClientAuthData) == "table" and ClientAuthData

				local GivenKey = ClientAuthData and ClientAuthData.NextAuth
				local RegisteredClientCalls = ClientAuthData and ClientAuthData.Calls

				if not GivenKey then
					return Warn(Player.Name, "did not include auth data, event requires auth data")
				end
				
				if type(GivenKey) == "string" then
					GivenKey = GivenKey:byte()
				end

				local ServerData = self:GetAuthData(MethodName, Player, ClientAuthData)
				
				local ExpectedKey = ServerData and ServerData.NextAuth
				local RegisteredServerCalls = ServerData and ServerData.Calls

				if GivenKey ~= ExpectedKey then
					return Warn(Player.Name, "failed auth check, Expected:", ExpectedKey, " Got:", GivenKey) 
				end
				
				if RegisteredClientCalls and (RegisteredServerCalls > RegisteredClientCalls) then
					return Warn(Player.Name, "Too many calls recieved, 3rd party tampering expected.")
				end

			end

			local Final = self:WrapData(_method, Arguments)

			return _method:Invoke( Player, unpack(Final) )
		end))

	else
		--// Client

		self.RemoteEvent:FireServer("__REQ_METHOD_CREATION_EVENT")

		table.insert(self.Connections, RemoteEvent.OnClientEvent:Connect(function(MethodName, Arguments)

			if MethodName == "__METHOD_CREATION_EVENT" then
				for _, Method in Arguments do
					local _method: Method? = self:_findMethod(Method)
					if not _method or _method.server_active then
						continue
					end

					_method.server_active = true
					for i,callback in pairs(_method.yielded) do
						_method.yielded[i] = nil
						callback()
					end
					Print(`Established Connection With Server Method "{Method}"`)
				end
				return
			end

			
			local _method: Method? = self:_findMethod(MethodName)
			if not _method then
				return
			end

			local Final = self:WrapData(_method, Arguments)
			_method:Invoke( unpack(Final) )

		end))

	end

	ParsedRemotes[RemoteEvent] = self

	return self
end



-- Confirm that the client is listening before firing events
function RemoteParser:_awaitServerActive(Method: string, Callback)
	local _method: Method? = self:_findMethod(Method)
	if
		not _method or
		not _method.config.secure or
		_method.server_active
	then
		-- if the method does not exist, the method is not secure, or the player is active:
		-- just run the callback
		return Callback()
	end

	table.insert(self.yielded, Callback)
end

function RemoteParser:FireServer(Method, ...)
	assert((not self.IsServer) and CheckEnv(), ":FireServer() can only be called from the Client")
	self.TotalCalls += 1

	local args = {...}
	local auth_data = self:GetAuthData(Method)

	self:_awaitServerActive(Method, function()
		return self.RemoteEvent:FireServer( Method, args, auth_data )
	end)
end

-- TODO: REMOVE, THIS IS FOR TESTING PACKET LOSS
function RemoteParser:FireServerDelayed(Method, ...)
	assert((not self.IsServer) and CheckEnv(), ":FireServer() can only be called from the Client")
	self.TotalCalls += 1

	local auth_data = self:GetAuthData(Method)
	local args = {...}

	task.delay(math.random() * 2, function()
		self:_awaitServerActive(Method, function()
			return self.RemoteEvent:FireServer( Method, args, auth_data )
		end)
	end)
end

function RemoteParser:FireClient(Player, Method, ...)
	assert(self.IsServer, ":FireClient() can only be called from the Server")
	self.RemoteEvent:FireClient( Player, Method, {...} )
end

function RemoteParser:FireAllClients(Method, ...)
	assert(self.IsServer, ":FireAllClients() can only be called from the Server")
	self.RemoteEvent:FireAllClients( Method, {...} )
end



function RemoteParser:GenerateSeed(Method)
	local jobId = game.JobId
	jobId = (jobId ~= "" and jobId) or "00000000-0000-0000-0000-000000000000"
	
	return ( bit(Method) + bit(jobId) ) * GLOBAL_CONFIG.extra_key
end

-- compile the required auth data from a method into a table
function RemoteParser:GetAuthData(Method: string, Player: Player?, ClientAuthData: {NextAuth: number, Calls: number}?): AuthData
	local _method: Method? = Method and self:_getMethod(Method)
	if not _method then
		return {}
	end

	local Data = {
		NextAuth = 0,
		Calls = 0
	}

	if (not self.IsServer) then
		--// Client

		_method.calls += 1
		
		Data.NextAuth = ("").char( _method.auth:NextInteger(1,100) ) -- prevent exploiters from hijacking string.char by using ("").char
		Data.Calls = _method.calls -- on client so _method.calls == number of times player called this method
		
	elseif Player then
		--// Server
		
		-- get existing auth data or create new auth data
		local auth = _method.auth[Player] or {
			Random = Random.new(_method.seed),
			NextAuth = nil,
			Calls = 1,
			CallHistory = {}
		}
		
		-- if a packet sends too early / out of order, cache the results
		--while ClientAuthData.Calls > auth.Calls do
		-- prevent an exploiter from passing math.huge into their call number and crashing the server.
		do
			local i = 1
			while i <= _method.callBufferSize and ClientAuthData.Calls > auth.Calls do
				auth.Calls += 1
				auth.CallHistory[auth.Calls] = auth.Random:NextInteger(1,100)

			end
		end

		for i,_ in pairs(auth.CallHistory) do
			if i >= (ClientAuthData.Calls - _method.callBufferSize) then
				break
			end
			auth.CallHistory[i] = nil
		end

		-- remove the auth because the same call will not be called twice
		Data.NextAuth = auth.CallHistory[ClientAuthData.Calls]
		auth.CallHistory[ClientAuthData.Calls] = nil

		--auth.CallHistory[ClientAuthData.Calls]
		--auth.Random:NextInteger(1,100)
		--Data.Calls = auth.Calls + 1

		_method.auth[Player] = auth
	end

	return Data
end

-- rewrap the data depending on settings
function RemoteParser:WrapData(_method: Method, Arguments: any): {any}
	if not _method.config.wrap_data and type(Arguments) == "table" then
		return table.clone(Arguments)
	else
		return {Arguments}
	end
end


-- get or create the method *Instantly* | used by hookMethod
function RemoteParser:_getMethod(Method: string): (Method, boolean)
	local _method = self.Methods[Method]
	local MethodExists = (_method and true) or false

	if not _method then
		_method = ScriptEvents.new()

		_method.name = Method
		_method.seed = self:GenerateSeed(Method)
		_method.auth = (self.IsServer and {}) or Random.new(_method.seed)
		if not self.IsServer then
			_method.yielded = {}
			_method.server_active = false
		end
		_method.calls = 1
		_method.config = {} -- settings applied inside of hookMethod
		
		self.Methods[Method] = _method

		self._internalEvents:Invoke("_MethodCreated", _method)
	end

	return _method, MethodExists
end

-- hook into the method and return the invoked state event.
function RemoteParser:_hookMethod(Method: string, secure: boolean?, wrap_data: boolean?, extra_settings: _InternalConfig?): any
	assert(Method, "Must Pass Method Name")

	local _method, MethodExists = self:_getMethod(Method)

	if not MethodExists then
		-- method was just created
		_method.config = extra_settings or {}
		_method.config.secure = secure
		_method.config.wrap_data = wrap_data
		_method.callBufferSize = _method.config.callBufferSize or GLOBAL_CONFIG.default_call_buffer_size
	end

	if secure and self.IsServer then
		self.RemoteEvent:FireAllClients("__METHOD_CREATION_EVENT", {Method})
	end

	return (_method and _method.Invoked)
end


-- Find an existing method. Yields if it cannot find the method
function RemoteParser:_findMethod(Method: string): Method?
	local _method = self.Methods[Method]

	if not _method and (not self.expired) and self.Created then

		while (tick() - self.Created) < GLOBAL_CONFIG.method_creation_timeout do
			local timeLeft = GLOBAL_CONFIG.method_creation_timeout - (tick() - self.Created)
			local eventType, method = self._internalEvents.Invoked:Wait(timeLeft)

			if eventType == "_MethodCreated" and method and method.name == Method then
				_method = method
				break
			end
		end

		self.expired = true
	end

	return _method
end



-- put down at the bottom for readiblity 
local function empty(t: {any}): {any}
	for i,v in t do
		if type(v) == "table" then
			empty(v)
		end
		t[i] = nil
	end

	return t
end


function RemoteParser:Destroy()
	for i,v in pairs(self.Connections) do
		v:Disconnect()
		self.Connections[i] = nil
	end

	empty(self)
end


if IsServer then

	-- clear player memory when they leave, weak tables dont work here
	Players.PlayerRemoving:Connect(function(Player)
		for _, parsed in pairs(ParsedRemotes) do
			for _,method in pairs(parsed.Methods) do
				method.auth[Player] = nil
			end
		end
	end)

end


return CheckEnv() and RemoteParser
