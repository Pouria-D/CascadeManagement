import json
# Third Party imports.
from channels.generic.websocket import WebsocketConsumer, AsyncWebsocketConsumer, JsonWebsocketConsumer
from channels.exceptions import DenyConnection
# Django imports.
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import AnonymousUser
# Local imports.
from DeviceManagement.models import Device
from utils.serializers import ping

from channels.consumer import SyncConsumer
from time import sleep
from DeviceManagement.serializers import DeviceSerializer
from rest_framework.response import Response
from json import JSONEncoder

    
class Temp_Device():
    def __init__(self, id, name, status, ip, address, port, Description):
        self.id = id
        self.name = name
        self.status = status
        self.ip = ip
        self.address = address
        self.port = port
        self.Description = Description

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)

class DeviceEncoder(JSONEncoder):
        def default(self, o):
            return o.__dict__

    # let's do a funny thing :)
    # we have problem by type of model device class and it's special serializer that can't use it manually out of views.py to print json form of a device so :
    # let's make a secon rutine class device and serialize it like any other python class ! I'm serious don't laugh at me :/
    
class StatusConsumer(WebsocketConsumer):
    groups = ['DeviceManagement']
    
    run_loop = False 

    devices = Device.objects.all()
    
    instances = []
    json_instances = []
    def connect(self):
        print("Welcom to my channel :)")
        self.accept()
        self.run_loop = True
        
        for instace in self.devices:
                temp_instance = Temp_Device(instace.id, instace.name , instace.status , instace.ip, instace.address, instace.port, instace.Description)
                self.instances.append(temp_instance)
                self.json_instances.append(json.dumps(temp_instance, indent=4, cls= DeviceEncoder))
        
        # Now all Devices are stored in 'instances' array and all Devices in json formatt are stored in 'json_instances' 
        # so we first send the initial list of devices :
        for obj in self.json_instances:
            self.send(obj)
        
        self.channel_layer.group_add("DeviceManagement", self.channel_name)
        

    def receive(self, text_data=None):
    
        while self.run_loop:
            i = 0
            flag = 0
            self.instances.clear()
            self.json_instances.clear()
            for instace in self.devices:
                instace.status = ping(instace.ip)
                instace.save()
                temp_instance = Temp_Device(instace.id, instace.name , instace.status , instace.ip, instace.address, instace.port, instace.Description)
                self.instances.append(temp_instance)
                self.json_instances.append(json.dumps(temp_instance, indent=4, cls= DeviceEncoder))
                """
                # Now update two arrays ; first check if any devices has been deleted from the list and if not check the status changings:
                if self.instances[i].id =! temp_instance.id:
                    if self.instances[i].status != temp_instance.status:
                        self.instances[i] = temp_instance
                        self.json_instances = json.dumps(temp_instance, indent=4, cls= DeviceEncoder)
                        flag = 1
                """
                i = i + 1

            # Now if status of any devices of list has changed it will return whole list again :
            #if flag == 1:            
            for obj in self.json_instances:
                self.send(obj)

            # time out to rest :))    
            sleep(5)

    def disconnect (self, close_code):
        self.run_loop = False
        pass

"""     
        #event = {'type': 'send_data'}
        #leads_as_json = DeviceSerializer('json', Device.objects.all())
        #return Response(leads_as_json.initial_data, content_type='json')
        #self.send_json(leads_as_json)

           # leads_as_json = DeviceSerializer('json', Device.objects.all())
            #return Response(leads_as_json.initial_data, content_type='json')

        #    self.send_json(leads_as_json)

#self.send_json(json.dumps(temp_instance.toJson() , indent=4))
                #self.send(json.dumps(temp_instance.toJson() , indent=4))

    def connect(self):
        print("********* Now it's the first Step ! **********")
        self.accept()
    def 
    def disconnect(self):
        pass


    def websocket_connect(self, event):
        print("Welcom to my channel :)", event)

        self.send({
            "type": "websocket.accept",
        })

    def websocket_receive(self, event):
        self.send({
            "type": "websocket.send",
            "text": "Received Text !",
        })
  
class StatusConsumer(WebsocketConsumer):
    #groups = ["broadcast"]
    
    def connect(self, event):
        #self.game = Game.objects.get(pk=self.room_name)
        #self.device = Device.objects.get(pk=self.id)    
        print("-----------WebSocket Connected-----------", event)
        self.accept()
        '''
        from channels.generic.websocket import AsyncWebsocketConsumer
        self.group_name = "snek_game"
        # Join a common group with all other players
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        '''

    def disconnect(self, close_code):
        pass

    def receive(self, text_data):
        device_ip = json.loads(text_data).get('ip')
    
        self.send(text_data=json.dumps({
                'status': ping(device_ip)
            }))
    

async def receive(self, text_data):
       game_city = json.loads(text_data).get('game_city')
       await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'live_score',
                'game_id': self.room_name,
                'game_city': game_city
            }
        )

        
async def live_score(self, event):
        city = event['game_city']
        # Here helper function fetches live score from DB.
        await self.send(text_data=json.dumps({
                'score': get_live_score_for_game(self.game, city)
            }))


    class LiveScoreConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['game_id']
        self.room_group_name = f'Game_{self.room_name}'
        if self.scope['user'] == AnonymousUser():
            raise DenyConnection("Invalid User")
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        # If invalid game id then deny the connection.
        try:
                
        except ObjectDoesNotExist:
                raise DenyConnection("Invalid Game Id")
        await self.accept()

    async def websocket_disconnect(self, message):
            # Leave room group
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )

    
    def check(self, Device[]):

        for item in Devices:
            item.status =  ping(item.ip)
            item.save()
    
    
    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']

        self.send(text_data=json.dumps({
            'message': message
        }))
"""