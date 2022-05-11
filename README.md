# RTKGPS-DataDistributor
RTKGPS-DataDistributor recieves TCP streams from Basestation and distributes it to Rover. Server also handles serving Rover position data using HTTPS. The application is used for RTK GPS positioning. Tested with U-Blox F9P reciever over 5G network.

Default basestation port is 1234 and server binds to all network interfaces (accepts only single connection)
Default rover post is 1235 and server binds to all network interfaces (accepts only single connection)

Default HTTPS server port is 4443 and server binds to all network interfaces. Application generates self-signed certificate for the HTTPS server (private.key and selfsigned.crt in application root folder).

Basestation and rover IP-addresses need to be added to whitelist that can be done by accessing the HTTPS server URI /add_to_whitelist

Latest Rover information can be fetched from the HTTPS server using URI /get_rover_data. Request returns latest data in JSON format
