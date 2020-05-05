local my_proto = Proto("QIESocket", "企鹅直播的 socket 协议解析", "tcp sample protocol")

--定义协议字段内容
local dataLen = ProtoField.uint32("dataLen", "包的长度", base.DEC);
local headLen = ProtoField.uint16("headLen", "header 长度", base.DEC);
local version = ProtoField.uint16("version", "版本号", base.DEC);
local operation = ProtoField.uint32("operation", "操作码", base.DEC);
local seqNO = ProtoField.uint32("seqNO", "确认号", base.DEC);
local content = ProtoField.string("content", "内容", base.STRING);

my_proto.fields = {dataLen, headLen, version, operation,  seqNO, content}
--协议分析器
function my_proto.dissector(buffer, pinfo, tree)
pinfo.cols.protocol:set("QIESocket")
    local len = buffer:len()
	local offset = 0

	while(offset ~= len)
	do
	    local myProtoTree = tree:add(my_proto, buffer(0, len), "tcp sample protocol")

	    myProtoTree:add(dataLen, buffer(offset, 4))
	    dataLenCurrent = buffer(offset, 4):uint()
	    offset = offset + 4

	    myProtoTree:add(headLen, buffer(offset, 2))
	    offset = offset + 2

	    myProtoTree:add(version, buffer(offset, 2))
	    offset = offset + 2

	    myProtoTree:add(operation, buffer(offset, 4))
	    offset = offset + 4

	    myProtoTree:add(seqNO, buffer(offset, 4))
	    offset = offset + 4

	    contentLen = dataLenCurrent - offset;
	    myProtoTree:add(content, buffer(offset, contentLen))
		offset = offset + contentLen

	end

end

local tcp_table = DissectorTable.get("tcp.port")
portArray = {3001, 3101, 3201, 31010}
for index = 1, #portArray do
	tcp_table:add(portArray[index], my_proto)
end

