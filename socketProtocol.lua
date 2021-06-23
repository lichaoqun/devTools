local my_protocol = Proto("QIESocket", "企鹅直播的 socket 协议解析", "企鹅直播socket协议")

--定义协议字段内容
local dataLen = ProtoField.uint32("qiesocket.dataLen", "包的长度", base.DEC);
local headLen = ProtoField.uint16("qiesocket.headLen", "header 长度", base.DEC);
local version = ProtoField.uint16("qiesocket.version", "版本号", base.DEC);
local operation = ProtoField.uint32("qiesocket.op", "操作码", base.DEC);
local seqNO = ProtoField.uint32("qiesocket.seq", "序号", base.DEC);
local content = ProtoField.string("qiesocket.content", "内容", base.STRING);

my_protocol.fields = {dataLen, headLen, version, operation,  seqNO, content}
--协议分析器
function my_protocol.dissector(buffer, pinfo, tree)
pinfo.cols.protocol:set("QIESocket")
    local len = buffer:len()
	local offset = 0

	while(offset ~= len)
	do
	    local myProtoTree = tree:add(my_protocol, buffer(0, len), "企鹅直播socket协议")

	    myProtoTree:add(dataLen, buffer(offset, 4))
	    curContentLen = buffer(offset, 4):uint()
	    offset = offset + 4

	    myProtoTree:add(headLen, buffer(offset, 2))
		curHeaderLen = buffer(offset, 2):uint()
	    offset = offset + 2

	    myProtoTree:add(version, buffer(offset, 2))
	    offset = offset + 2

	    myProtoTree:add(operation, buffer(offset, 4))
	    offset = offset + 4

	    myProtoTree:add(seqNO, buffer(offset, 4))
	    offset = offset + 4

	    contentLen = curContentLen - curHeaderLen
	    myProtoTree:add(content, buffer(offset, contentLen))
		offset = offset + contentLen

	end

end

local tcp_table = DissectorTable.get("tcp.port")
for index = 6410, 6420, 1 do
	tcp_table:add(index, my_protocol)
tcp_table:add(3101, my_protocol)
tcp_table:add(3201, my_protocol)
tcp_table:add(31010, my_protocol)
tcp_table:add(3001, my_protocol)
end

