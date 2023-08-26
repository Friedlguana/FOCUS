from colorama import Fore
import threading, time, psutil, webbrowser
from functions import port_scanner, clear, pushbullet_noti, PortCloser ,OpenPorts

while True:
    #Display project name
    clear()
    print("")
    print(f'{Fore.LIGHTRED_EX}🎯    ███████╗     ██████╗      ██████╗    ██╗   ██╗    ███████╗    🎯')
    print(f'  🎯  ██╔════╝    ██╔═══██╗    ██╔════╝    ██║   ██║    ██╔════╝  🎯  ')
    print(f'🎯    █████╗      ██║   ██║    ██║         ██║   ██║    ███████╗    🎯')
    print(f'  🎯  ██╔══╝      ██║   ██║    ██║         ██║   ██║    ╚════██║  🎯  ')
    print(f'🎯    ██║         ╚██████╔╝    ╚██████╗    ╚██████╔╝    ███████║    🎯')
    print(f'  🎯  ╚═╝          ╚═════╝      ╚═════╝     ╚═════╝     ╚══════╝  🎯  ')
    print(f"{Fore.BLUE}ᴀ ᴄʏʙᴇʀꜱᴇᴄᴜʀɪᴛʏ ꜰʀᴀᴍᴇᴡᴏʀᴋ ᴅᴇᴠᴇʟᴏᴘᴇᴅ ꜰᴏʀ ᴇɴᴛᴇʀᴘʀɪꜱᴇ ɴᴇᴛᴡᴏʀᴋ ᴘʀᴏᴛᴇᴄᴛɪᴏɴ")
    print(Fore.RESET)

    #Display project options
    print(f"{Fore.CYAN}Options -")
    print("")
    print(f"{Fore.GREEN}1."f"{Fore.MAGENTA} Port Scanner")
    print(f"{Fore.GREEN}2."f"{Fore.MAGENTA} Github Link")
    print('')
    print(f"{Fore.GREEN}0."f"{Fore.MAGENTA} Exit Program")

    print(f"{Fore.CYAN}")
    #Wait on user input
    UserInput1 = (input(">  "))

    #Input Tree
    if UserInput1.strip() == '1':
        clear()
        print('Port scanner is Running...')
        # Formatting Whitelist Ports
        with open('Whitelisted Ports.txt', 'r') as WhitelistedPortsFile:
            WhitelistedPortsList = [int(port.strip()) for port in WhitelistedPortsFile.readlines()]

        # Port scanning via multi-thread distribution
        start = time.time()  # Function Start Time
        for port in range(1, 65536):
            if port in WhitelistedPortsList:
                continue

            thread = threading.Thread(target=port_scanner, args=[port])
            thread.start()

        end = time.time()  # Function End Time

        #Message formatting
        message = ''
        for port in OpenPorts:
            message = message + str(port) + '\n'

        if len(OpenPorts) == 0:
            print('No port detected.')
        else:
            #Port closer
            print('Attempting to close ports...')
            for port in OpenPorts:
                PortCloser(port)
            print("")
            print("")
            print("Scan Complete!")
            print(f"Time taken for scan: {end - start} Seconds")
            print('Hit enter to continue...')
            input()

    elif UserInput1.strip() == '2':
        clear()
        print(webbrowser.open('https://github.com/Friedlguana/FOCUS'))

    elif UserInput1.strip() == '0':
        break
    
    else:
        clear()
        print('Invalid Input. Hit enter to return')
        input()