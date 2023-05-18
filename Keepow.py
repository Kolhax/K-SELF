import discord
from discord.ext import commands
import os
import time
import json
from colorama import Fore, init
import re
import httpx
import random
import hmtai
import requests
import nmap
import string

def pasteupload(content):
    post = requests.post("https://paste.kepar.ml/documents", data=content.encode('utf-8'))
    return "https://paste.kepar.ml/" + post.json()["key"]

init()

banner = """  
 /$$   /$$        /$$$$$$            /$$  /$$$$$$ 
| $$  /$$/       /$$__  $$          | $$ /$$__  $$
| $$ /$$/       | $$  \__/  /$$$$$$ | $$| $$  \__/
| $$$$$/ /$$$$$$|  $$$$$$  /$$__  $$| $$| $$$$    
| $$  $$|______/ \____  $$| $$$$$$$$| $$| $$_/    
| $$\  $$        /$$  \ $$| $$_____/| $$| $$      
| $$ \  $$      |  $$$$$$/|  $$$$$$$| $$| $$      
|__/  \__/       \______/  \_______/|__/|__/      
                                                  
"""

def Login():
    global prefix
    os.system('cls')
    os.system('title K-Self ^| Login')
    print(banner)
    token = input(f"K-Self@{os.getenv('USERNAME')} > Enter your discord token:  ")
    prefix = input(f"K-Self@{os.getenv('USERNAME')} > Enter the bot prefix desired: ")
    print()
    print('You are almost there :)')
    time.sleep(5)
    a = {}
    a["prefix"] = prefix
    a["token"] = token
    return a

def Welcome():
    os.system('cls')
    os.system('title K-Self ^| Disclamer')
    print('Welcome to K-Self, I hope you will be able to do what you want :)\nFeel Free.\n\nNote:\nI am not responsible for any bans or expulsion,\nNuke tools are highly flagged by discord and might cause an account ban if abused!')
    time.sleep(5)
    os.system('cls')

creds = Login()
Welcome()


bot = commands.Bot(command_prefix=creds['prefix'], self_bot=True)

class ktools(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    
    @commands.command()
    async def nitrosnipper(self,ctx):
        with open("setting.json","r") as f:
            a = json.load(f)
        if a["nitrosniper"] == "True":
            a["nitrosniper"] = "False"
            with open("setting.json","w") as f:
                    json.dump(a, f)
            print("[>]  Nitro Snipper Has been **Deactivated**")
            await ctx.message.edit("🔻 Nitro Snipper Has been **Deactivated**",delete_after=30)
        elif a["nitrosniper"] == "False":
            a["nitrosniper"] = "True"
            with open("setting.json","w") as f:
                json.dump(a, f)
            print("[>]  Nitro Snipper Has been **Activated**")
            await ctx.message.edit("🔫 Nitro Snipper Has been **Activated**",delete_after=30) 
        else:
            print("[>]  'setting.json' can't be loaded...")
            await ctx.message.edit("😐 'setting.json' can't be loaded...",delete_after=30) 

    @commands.command()
    async def logchannel(self,ctx):
        with open("setting.json","r") as f:
            a = json.load(f)
        a['channellog'] = str(ctx.channel.id)
        with open("setting.json","w") as f:
            json.dump(a, f)
        await ctx.message.edit("🧐 Monitoring messages in this channel, look in the 'MessageLogs' folder.",delete_after=30)
        print(f"[>] Monitoring messages in {a['channellog']}, look in the 'MessageLogs' folder.")

    @commands.command()
    async def stoplogchannel(self,ctx):
        with open("setting.json","r") as f:
            a = json.load(f)
        chan = a['channellog']
        a['channellog'] = ""
        with open("setting.json","w") as f:
            json.dump(a, f)
        await ctx.message.edit(f"💤 Stopped logging message in: <#{chan}>",delete_after=30)     
        print(f"[>] Stopped logging message in: {chan}")

class moderation(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    
    @commands.command()
    async def kick(self,ctx, member: discord.Member, *, reason=None):
        if ctx.author.guild_permissions.kick_members:
            await member.kick(reason=reason)
            await ctx.message.edit(f'{member.mention} has been kicked.',delete_after=30)
            print(f"[>]  {member.mention} has been kicked.")
        else:
            await ctx.message.edit('You do not have permission to kick members.',delete_after=30)
            print(f"[>]  You do not have permission to kick members.")

    @commands.command()
    async def ban(self,ctx, member: discord.Member, *, reason=None):
        if ctx.author.guild_permissions.ban_members:
            await member.ban(reason=reason)
            await ctx.message.edit(f'{member.mention} has been banned.',delete_after=30)
            print(f"[>] {member.mention} has been banned.")
        else:
            await ctx.message.edit('You do not have permission to ban members.',delete_after=30)
            print(f"[>] You do not have permission to ban members.")

    @commands.command()
    async def clear(self,ctx, amount=5):
        if ctx.author.guild_permissions.manage_messages:
            await ctx.channel.purge(limit=amount+1)
            await ctx.message.edit(f'{amount} messages cleared.', delete_after=5)
            print(f"[>] {amount} messages cleared.")
        else:
            await ctx.message.edit('You do not have permission to manage messages.',delete_after=30)
            print(f"[>] You do not have permission to manage messages.")

class images(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    
    @commands.command()
    async def nsfw(self,ctx,category=None):
        lis = ["ass","anal","bdsm","classic","cum","creampie","manga","femdom","hentai","incest","masturbation","public","ero","orgy","elves","yuri","pantsu","pussy","glasses","cuckold","blowjob","boobjob","handjob","footjob","boobs","thighs","ahegao","uniform","gangbang","tentacles","gif","nsfwNeko","nsfwMobileWallpaper","zettaiRyouiki"]
        if category is None:
            choice = random.choice(lis)
            l = hmtai.get("hmtai",choice)
            print(f"[>]  NSFW Image generated, hehe naughty... type: {choice}")
        else:
            if category not in lis:
                choice = random.choice(lis)
                l = hmtai.get("hmtai",choice)
                print(f"[>]  NSFW Image generated, hehe naughty... type: {choice}")
            else:
                l = hmtai.get("hmtai",category)
                print(f"[>]  NSFW Image generated, hehe naughty... type: {category}")
        
        await ctx.message.edit(f"{l}")

    @commands.command()
    async def meme(self,ctx):
        a = requests.get("https://meme-api.com/gimme")
        b=a.json()
        await ctx.message.edit(f"{b['url']}")
        print(f"[>]  MEME Image generated")

class osint(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
    
    @commands.command()
    async def osintdiscord(self,ctx,userid=None):
        if userid is None:
            await ctx.message.edit('🤨 Enter an ID, e.g., `!osintdiscord 732328815652634765`',delete_after=30)
            return

        req = requests.get(f"https://discordlookup.mesavirep.xyz/v1/user/{userid}")
        jj = req.json()
        try:
            member = bot.get_user(int(userid))
        except: pass
        jj['creationdate'] = member.created_at.timestamp()
        await ctx.message.edit(f"🥱 Result for: **{userid}**\n```{str(json.dumps(jj,indent=2))}```",delete_after=30)
        print(f"[>]  Discord Infos for {userid} has been retreived")

    @commands.command()
    async def osintusername(self,ctx,username=None):
        if username is None:
            await ctx.message.edit('🤨 Enter an Username, e.g., `!osintusername kepar`',delete_after=30)
            return
        await ctx.message.edit('🤓 LOADING!!! (other commands might not work while running this querry)')
        os.system(f'cmd /c py OsintTools\\maigret\\maigret.py {username} --skip-errors --output result.txt')
        with open("result.txt","r") as f:
            data = f.read()
        await ctx.message.edit(f"🥱 Result for: **{username}** ```{pasteupload(data)}```",delete_after=30)
        print(f"[>]  OSINT of: {username} has been completed")
        os.remove('result.txt')
    
    @commands.command()
    async def osintwhois(self,ctx,domainip=None):
        if domainip is None:
            await ctx.message.edit('🤨 Enter an a Domain or IP, e.g., `!osintwhois domaintools.com',delete_after=30)
            return
        req = requests.get(f"https://api.domaintools.com/v1/{domainip}/whois/")
        jj = req.json()
        await ctx.message.edit(f"🥱 Result for: **{domainip}**\n```{str(json.dumps(jj,indent=2))}```",delete_after=30)
        print(f"[>]  WHOIS, so who was '{domainip}'?,WHOIS Scan has been completed")
    
    @commands.command()
    async def osintiplookup(self,ctx,ip=None):
        if ip is None:
            await ctx.message.edit('🤨 Enter an a Domain or IP, e.g., `!osintiplookup 72.15.6.150',delete_after=30)
            return
        await ctx.message.edit('🤓 LOADING!!! (other commands might not work while running this querry)')
        req = requests.get(f"http://ip-api.com/json/{ip}")
        jj = req.json()
        nm = nmap.PortScanner()
        ip = str(ip)
        nm.scan(ip, '1-25565')
        ports = ''
        for host in nm.all_hosts():
            ports += ('----------------------------------------------------'+'\n')
            ports += ('Host : %s (%s)' % (host, nm[host].hostname())+ '\n')
            ports += ('State : %s' % nm[host].state()+ '\n')
            for proto in nm[host].all_protocols():
                ports += ('----------'+ '\n')
                ports += ('Protocol : %s' % proto+ '\n')
                lport = nm[host][proto].keys()
                sorted(lport)
                for port in lport:
                    ports += ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state'])+ '\n')
            ports += ('----------')

        await ctx.message.edit(f"🥱 Result for: **{ip}**\n```{str(json.dumps(jj,indent=2))}```\n```{ports}```",delete_after=30)
        print(f"[>]  IPLOOKUP, for metasploit?, OSINTIPLOOKUP Completed")

class random(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def ghostmsg(self,ctx,*,message):
        await ctx.message.delete()
        a = await ctx.send(message + " 👻")
        await a.delete()
        print(f"[>]  GHOSTMSG, pikaboo")
    
    @commands.command()
    async def fakenitro(self,ctx):  
        code = "".join(random.choices(
            string.ascii_uppercase + string.digits + string.ascii_lowercase,
            k = 16
        ))
        nitro = f"https://discord.gift/{code}"  
        await ctx.message.edit(nitro)
        print(f"[>]  FakeNitro, Don't forget those are just random strings...")

    @commands.command()
    async def poll(self,ctx,*,message):
        await ctx.message.edit(f'{message}')
        await ctx.message.add_reaction("🔼")
        await ctx.message.add_reaction("🔻")
        print(f"[>]  POLL, i would say uh...., can a bot participate?")

class nuker(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def nuke(self,ctx,code=None):
        nukeconfirm = None
        if code is None:
            nukeconfirm = "".join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase,k = 16))
            await ctx.message.edit(f'Nuker might get you ban,\nNot only from the server, but also from discord...\nConfirm The attack by doing: ```{prefix}nuke {nukeconfirm}```')
        else:
            if nukeconfirm == None:
                nukeconfirm = "".join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase,k = 16))
                await ctx.message.edit(f'Nuker might get you ban,\nNot only from the server, but also from discord...\nConfirm The attack by doing: ```{prefix}nuke {nukeconfirm}```')
            elif code == nukeconfirm:
                for c in ctx.guild.channels: # iterating through each guild channel
                    try:
                        await c.delete()
                    except:
                        print("Error deleting guild channel...")
                for i in range(5):
                    guild = ctx.message.guild
                    c = await guild.create_text_channel('F-OFF')
                    c.send('@everyone, Rip the server i guess...')
                for role in ctx.guild.roles:  
                    try:  
                        await role.delete()
                    except:
                        await ctx.send(f"Cannot delete {role.name}")
                print('[>]  NUKER ,*rolling eyes* this was easy, NUKER Completed')
            else:
                await ctx.message.edit(f'😖 Did Not Nuked, Invalid code or error while starting the nuker..')
                print('[>]  Did Not Nuked, Invalid code or error while starting the nuker..')

    @commands.command()
    async def deletechannels(self,ctx,code=None):
        deletechannelsconfirm = None
        if code is None:
            deletechannelsconfirm = "".join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase,k = 16))
            await ctx.message.edit(f'Nuker might get you ban,\nNot only from the server, but also from discord...\nConfirm The attack by doing: ```{prefix}deletechannels {deletechannelsconfirm}```')
        else:
            if deletechannelsconfirm == None:
                deletechannelsconfirm = "".join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase,k = 16))
                await ctx.message.edit(f'Nuker might get you ban,\nNot only from the server, but also from discord...\nConfirm The attack by doing: ```{prefix}deletechannels {deletechannelsconfirm}```')
            elif code == deletechannelsconfirm:
                for c in ctx.guild.channels: # iterating through each guild channel
                    try:
                        await c.delete()
                    except:
                        print("Error deleting guild channel...")
                print('[>]  DELETECHANNELS i can already see the kid asking to admin where is #general XD')
            else:
                await ctx.message.edit(f'😖 Did Not Nuked, Invalid code or error while starting the nuker..')
                print('[>]  Did Not Nuked, Invalid code or error while starting the nuker..')

    @commands.command()
    async def deleteroles(self,ctx,code=None):
        deleterolesconfirm = None
        if code is None:
            deleterolesconfirm = "".join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase,k = 16))
            await ctx.message.edit(f'Nuker might get you ban,\nNot only from the server, but also from discord...\nConfirm The attack by doing: ```{prefix}deleteroles {deleterolesconfirm}```')
        else:
            if deleterolesconfirm == None:
                deletechannelsconfirm = "".join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase,k = 16))
                await ctx.message.edit(f'Nuker might get you ban,\nNot only from the server, but also from discord...\nConfirm The attack by doing: ```{prefix}deleteroles {deleterolesconfirm}```')
            elif code == deleterolesconfirm:
                for role in ctx.guild.roles:  
                    try:  
                        await role.delete()
                    except:
                        await ctx.send(f"Cannot delete {role.name}")
                print('[>]  DELETEROLES, ANARCHY HAS BEGUN!')
            else:
                await ctx.message.edit(f'😖 Did Not Nuked, Invalid code or error while starting the nuker..')
                print("[>]  Did Not Nuked, Invalid code or error while starting the nuker..")

    @commands.command()
    async def spam(self, ctx,*,message):
        a = 20
        for i in range(a):
            try:
                await ctx.send(f'message')
            except:
                print('Failed to send a message') 
            time.sleep(2)
        print("[>] SPAM , oops the cat was sitting on my keyboard, SPAM Completed")

@bot.listen('on_message')
async def messagelistener(message):
    if os.path.isfile("setting.json"):
        with open("setting.json","r") as f:
            a = json.load(f)
        if a["nitrosniper"] == "True":
            codeRegex = re.compile("(discord.com/gifts/|discordapp.com/gifts/|discord.gift/)([a-zA-Z0-9]+)")
            if codeRegex.search(message.content):
                print(Fore.LIGHTBLUE_EX + time.strftime("%H:%M:%S ", time.localtime()) + Fore.RESET, end='')
                code = codeRegex.search(message.content).group(2)
                start_time = time.time()
                if len(code) < 16:
                    try:
                        print(
                            Fore.LIGHTRED_EX + "[=] Auto-detected a fake code: " + code + " From " + message.author.name + "#" + message.author.discriminator + Fore.LIGHTMAGENTA_EX + " [" + message.guild.name + " > " + message.channel.name + "]" + Fore.RESET)
                    except:
                        print(
                            Fore.LIGHTRED_EX + "[=] Auto-detected a fake code: " + code + " From " + message.author.name + "#" + message.author.discriminator + Fore.RESET)
                else:
                    async with httpx.AsyncClient() as client:
                        result = await client.post(
                            'https://discordapp.com/api/v6/entitlements/gift-codes/' + code + '/redeem',
                            json={'channel_id': str(message.channel.id)},
                            headers={'authorization': creds["token"], 'user-agent': 'Mozilla/5.0'})
                        delay = (time.time() - start_time)
                        try:
                            print(
                                Fore.LIGHTGREEN_EX + "[-] Sniped code: " + Fore.LIGHTRED_EX + code + Fore.RESET + " From " + message.author.name + "#" + message.author.discriminator + Fore.LIGHTMAGENTA_EX + " [" + message.guild.name + " > " + message.channel.name + "]" + Fore.RESET)
                        except:
                            print(
                                Fore.LIGHTGREEN_EX + "[-] Sniped code: " + Fore.LIGHTRED_EX + code + Fore.RESET + " From " + message.author.name + "#" + message.author.discriminator + Fore.RESET)
                    if 'This gift has been redeemed already' in str(result.content):
                        print(Fore.LIGHTBLUE_EX + time.strftime("%H:%M:%S ", time.localtime()) + Fore.RESET, end='')
                        print(Fore.LIGHTYELLOW_EX + "[-] Code has been already redeemed" + Fore.RESET,
                            end='')
                    elif 'nitro' in str(result.content):
                        print(Fore.LIGHTBLUE_EX + time.strftime("%H:%M:%S ", time.localtime()) + Fore.RESET, end='')
                        print(Fore.GREEN + "[+] Code applied" + Fore.RESET, end='')
                    elif 'Unknown Gift Code' in str(result.content):
                        print(Fore.LIGHTBLUE_EX + time.strftime("%H:%M:%S ", time.localtime()) + Fore.RESET, end='')
                        print(Fore.LIGHTRED_EX + "[-] Invalid Code" + Fore.RESET, end=' ')
                    print(" Delay:" + Fore.GREEN + " %.3fs" % delay + Fore.RESET)

        if str(message.channel.id) == a['channellog']:
            with open(f"MessageLogs/{str(message.channel.id)}.txt","a") as f:
                f.write(f'[{message.created_at}]{message.author} | {message.channel.name} | {message.content}\n')
            
    else:
        print("Setting.json can't be found, please bring it back again, download template from the github.")
        exit()

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.message.edit("😫 You are missing a required argument. Please check the command usage.")

@bot.event
async def on_ready():
    os.system('cls')
    os.system('title K-Self ^| Bot Online')
    await bot.add_cog(ktools(bot))
    await bot.add_cog(moderation(bot))
    await bot.add_cog(images(bot))
    await bot.add_cog(osint(bot))
    await bot.add_cog(random(bot))
    await bot.add_cog(nuker(bot))
    print(banner)
    print('Logs:\n\n')
    
bot.run(creds['token'])
