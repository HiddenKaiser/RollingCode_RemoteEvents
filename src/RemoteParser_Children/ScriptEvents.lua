local Connection = {}

local ConnectionBase = {}
local InvokedBase = {}
ConnectionBase.__index = ConnectionBase
InvokedBase.__index = InvokedBase

function ConnectionBase:Invoke(...)
	for _, Data in next, self.Listeners do
		coroutine.wrap(Data.Callback)(...)
	end
	for i,v in next, self.Yielded do
		self.Yielded[i] = nil
		coroutine.resume(v, ...)
	end
end

function ConnectionBase:Fire(...)
	return self:Invoke(...);
end

function InvokedBase:Connect(f)
	local Connection = self.INTERNAL_Reference
	local Timestamp = os.clock()

	local Data = {
		Disconnect = function(self)
			self.Connected = false
			Connection.Listeners[Timestamp] = nil
		end,
		Callback = f,
		Connected = true
	}

	Connection.Listeners[Timestamp] = Data

	return Data;
end

function InvokedBase:Wait()
	local Connection = self.INTERNAL_Reference
	Connection.Yielded[#Connection.Yielded + 1] = coroutine.running()
	return coroutine.yield()
end

function Connection.new()
	local Meta = setmetatable({
		Listeners = {},
		Invoked = setmetatable({INTERNAL_Reference = false}, InvokedBase),
		Yielded = {}
	}, ConnectionBase);

	Meta.Invoked.INTERNAL_Reference = Meta;
	Meta.Event = Meta.Invoked;
	
	return Meta;
end

function Connection:Destroy()
	for ts,connection in pairs(self.Listeners) do
		connection:Disconnect();
	end

	for index, _ in pairs(self) do
		self[index] = nil;
	end

	-- remove all metamethods and mark table for garbage collection
	self.__index = nil;
	setmetatable(self, nil);
	setmetatable(self, {__mode = "kv"});
end

return Connection;