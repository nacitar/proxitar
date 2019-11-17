from .alertbot import AlertBot

def setup(bot):
    bot.add_cog(AlertBot())