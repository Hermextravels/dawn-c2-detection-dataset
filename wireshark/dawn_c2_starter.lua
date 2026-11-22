-- STARTING ARTIFACT (intentionally unfinished); not a validated production dissector.
-- Original synthetic protocol only. It is not a real malware decoder.
local p = Proto('dawnc2', 'Dawn Synthetic C2 Protocol')
local f_magic = ProtoField.string('dawnc2.magic', 'Magic')
local f_version = ProtoField.uint8('dawnc2.version', 'Version', base.DEC)
local f_type = ProtoField.uint8('dawnc2.type', 'Message type', base.DEC, {
  [1]='HELLO',[2]='CHECKIN',[3]='COMMAND',[4]='RESULT',[5]='KEEPALIVE'})
p.fields = {f_magic,f_version,f_type}
local PORTS = {1177,8443}

function p.dissector(tvb,pinfo,tree)
  if tvb:len()<6 then return 0 end
  if tvb(0,4):string()~='DNC2' then return 0 end
  local subtree = tree:add(p,tvb(),'Dawn Synthetic C2 (starter decoder)')
  subtree:add(f_magic,tvb(0,4))
  subtree:add(f_version,tvb(4,1))
  subtree:add(f_type,tvb(5,1))
  pinfo.cols.protocol='DAWNC2'
  -- TODO 1: Parse the 18-byte fixed header and validate magic/version/type/length.
  -- TODO 2: Introduce TCP reassembly (pinfo.desegment_offset/desegment_len).
  -- TODO 3: Loop through several messages carried in one segment.
  -- TODO 4: Expose session ID, message sequence, payload length and error fields.
  -- TODO 5: Make malformed and benign lookalike handling robust.
  -- TODO 6: Validate each capture using validation/*expected-messages.csv.
  return tvb:len()
end

for _,port in ipairs(PORTS) do DissectorTable.get('tcp.port'):add(port,p) end
