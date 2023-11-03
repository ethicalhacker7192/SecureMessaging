# SecureMessaging
A module for messaging securely.
GuineaBot3 v4.0.5, Copyright © 2022 GuineaPigLord. All rights reserved.

Pretty much the same thing as GuineaSend but more lightweight.

More info [here](https://github.com/ethicalhacker7192/OTP-MAC-online)

## INSTALLATION

for pip and pip3:

pip:

    pip install SecureMessaging

pip3:

    pip3 install SecureMessaging

for windows:

    py -m pip install SecureMessaging

for linux (without pip command line tool):

    python3 -m pip install SecureMessaging

## Usage

You may be wondering how to use this module, there are 4 functions that are mainly used:

sending:
    send_message('[your reciever's IP]', "[your message]")

receiving:

    receive_message()

transceiving:

    transceive_message()

fetching the IP of client:

    get_ip_address()
    # this prints your IP, however, here is one that you can use as a varable later for some reason:
    x = get_ip_address()
    # Then in the future
    print(x)


these are the main functions, also I will add a example usage of the entire module here in different ways:

sending:

    import SecureMessaging as sm

    x = sm.get_ip_address()
    print(x)
    sm.send_message('127.0.0.1', x) #you can do anything you want to this example

the reciever side:

    import SecureMessaging as sm

    sm.receive_message()
    
you can do a lot with these functions, you just need to know how to do them.
