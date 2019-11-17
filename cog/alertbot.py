from redbot.core import commands

import lavalink
import time

# DeepHorizons tts
import tts.sapi
import subprocess
import os

THIS_SCRIPT_DIRECTORY = os.path.dirname(os.path.realpath(__file__))
# Must be placed alongside this file!
# TODO: detect it if in path?
FLAC_BINARY = os.path.join(THIS_SCRIPT_DIRECTORY, 'flac.exe')
# TODO: might have to create this directory's last component
LOCALTRACKS_DIR = os.path.join(THIS_SCRIPT_DIRECTORY, '..', '..', '..', 'Audio', 'localtracks')
VOICE_WAV_FILE = os.path.join('files', 'test.wav')
VOICE_WAV_FILE_ABS = os.path.join(LOCALTRACKS_DIR, VOICE_WAV_FILE)
VOICE_FLAC_FILE = os.path.join('files', 'test.flac')
VOICE_FLAC_FILE_ABS = os.path.join(LOCALTRACKS_DIR, VOICE_FLAC_FILE)


async def get_player(ctx):
    # If we're already there, nothing bad happens.. easy logic
    await lavalink.connect(ctx.author.voice.channel)
    return lavalink.get_player(ctx.guild.id)

class AlertBot(commands.Cog):  
    @commands.command()
    async def mycom(self, ctx, *args):
        """This does stuff!"""
        global FLAC_BINARY
        global VOICE_WAV_FILE
        global VOICE_FLAC_FILE
        player = await get_player(ctx)
        await player.stop()
        message = ' '.join(args)
        voice = tts.sapi.Sapi()
        #voice.set_voice("Anna")
        voice.create_recording(VOICE_WAV_FILE_ABS, message)
        arguments = [FLAC_BINARY, '-o', VOICE_FLAC_FILE_ABS, '--fast', VOICE_WAV_FILE_ABS, '--force']
        child = subprocess.Popen(arguments, stdin = subprocess.DEVNULL, stderr = subprocess.DEVNULL)  #  stdout = subprocess.DEVNULL,
        child.wait()
        tracks = await player.get_tracks(os.path.join('localtracks', VOICE_FLAC_FILE))
        track = tracks[0]
        player.add(ctx.author, track)
        #player.add(player.channel.guild.me, track)
        await player.play()
        #time.sleep(track.length/1000)
        #await ctx.send("Done playing!")
