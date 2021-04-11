--Per tutti i protocolli
--- numero di hosts diversi contattattati (client)
--- numero di hosts diversi da cui sono stati contattati (server)
--per tutti i protocolli intendevo “a prescindere dal protocollo” ovvero senza differenziare DNS o TLS ad esempio.
--Per fare qeusto esercizio usate pure una hash o simile, anche se poi tra un pochino vi faccio vedere delle strutture dati ad hoc a lezione
--(es vd https://github.com/avz/hll). 
--Il client si intente colui che inizia la comunicazione 
--(quelloc he manda il SYN in TCP per intenderci,
--mentre su UDP chi della 5-tupla IP src/dst,ports src/dst e protocollo invia il pacchetto per primo). Per semplicita’ potreste considerare
--le coppie IP src-IP dst lasciando il discorso client/server a quando vi spiego meglio come analizzare questi dati. 
-- Non metterei di certo un parametro nel codice.

local f_ip_src = Field.new("ip.src")
local f_ip_dst = Field.new("ip.dst")
local f_tcp_flags  = Field.new("tcp.flags")
local f_tcp_flags_syn  = Field.new("tcp.flags.syn")
local f_tcp_flags_ack  = Field.new("tcp.flags.ack")

local function getstring(finfo)
   local ok, val = pcall(tostring, finfo)
   if not ok then val = "(unknown)" end
   return val
end

local function gr_tap()
   -- Declare the window we will use
   local tw = TextWindow.new("Client Server")
   
   -- Dictionary key:hostname value:boolean representing its presence ad client
   local clients = {}
   local servers = {}

   -- this is our tap
   local tap = Listener.new();

   local function remove()
      -- this way we remove the listener that otherwise will remain running indefinitely
      tap:remove();
   end

   -- we tell the window to call the remove() function when closed
   tw:set_atclose(remove)

   -- this function will be called once for each packet
   function tap.packet(pinfo,tvb)
    -- Call all the function that extracts the fields
      local ip_src = f_ip_src()
      local tcp_flags = f_tcp_flags()
      local tcp_flags_syn = f_tcp_flags_syn() 
      local tcp_flags_ack = f_tcp_flags_ack()

      --Check if it's a tcp packet and contains an IP source (maybe we can't get src information a non-IP datagram)
      if(tcp_flags ~= nil and ip_src.value ~= nil) then
        --Check if the SYN flag is 1 (if it isn't it's just a TCP segment of an already enstablished connection)
        if(tcp_flags_syn.value) then
          --If ACK is set to 1 then the src is the Server that sends the second segment of the 3 way handshake 
          if(tcp_flags_ack.value) then
            if(servers[getstring(ip_src.value)] == nil) then
              servers[getstring(ip_src.value)]=true
            end
          --Else is the client that starts the communication with just a SYN
          else
            if (clients[getstring(ip_src.value)] == nil) then
              clients[getstring(ip_src.value)]= true
            end
          end
        end 
      end
   end

   -- this function will be called once every few seconds to update our window
   function tap.draw(t)
        tw:clear()
        local tot_clients=0
        local tot_servers=0

        tw:append("Clients: " .. "\n")
        for host,flag in pairs(clients) do
            tw:append(getstring(host) .. "\n")
            if(flag) then
              tot_clients = tot_clients + 1
            end
        end

        tw:append("Servers: " .. "\n")
        for host,flag in pairs(servers) do
          tw:append(getstring(host) .. "\n")
          if(flag) then
            tot_servers = tot_servers + 1
          end
        end

       tw:append("Total clients: " .. tot_clients .. "\n")
       tw:append("Total servers: " .. tot_servers .. "\n")
   end

   -- this function will be called whenever a reset is needed
   -- e.g. when reloading the capture file
   function tap.reset()
      --tw:clear()
      tot_clients=0
      tot_servers=0
      clients = {}
      servers = {}
   end

   -- Ensure that all existing packets are processed.
   retap_packets()
end

-- Menu GR -> Packets
register_menu("Gruppo9/Client Server", gr_tap, MENU_TOOLS_UNSORTED)

