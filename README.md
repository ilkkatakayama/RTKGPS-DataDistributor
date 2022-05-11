# RTKGPS-DataDistributor
RTKGPS-DataDistributor receives TCP stream from Basestation and distributes it to Rover. The server also handles serving Rover position data using HTTPS. The application is used for RTK GPS positioning. Tested with U-Blox F9P receivers over 5G network.

The default base station port is 1234 and the server binds to all network interfaces (accepts only a single connection)

The default rover port is 1235 and the server binds to all network interfaces (accepts only a single connection)

The default HTTPS server port is 4443 and the server binds to all network interfaces. The application generates a self-signed certificate for the HTTPS server (private.key and selfsigned.crt in the application root folder).

Basestation and rover IP addresses need to be added to the whitelist that can be done by accessing the HTTPS server URI /add_to_whitelist

Latest Rover information can be fetched from the HTTPS server using URI /get_rover_data. Request returns latest data in JSON format
