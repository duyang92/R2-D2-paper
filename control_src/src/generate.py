import Data
import sketch
import copy
import traceback
import logging
import time

import sys
sys.path.append('/root/bf-sde-9.2.0/install/lib/python2.7/site-packages/tofino')

import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

alloc_time = 0

class Task:
    def __init__(self, task_name, task_id, sketch_id):
        self.task_name = task_name
        self.task_id = task_id
        self.sketch_id = sketch_id
        self.defense_stage = 0
        self.offsets = [-1,-1,-1,-1]

    def print_task(self):
        print("task_name = ", self.task_name)
        print("task_id = ", self.task_id)
        print("sketch_id = ", self.sketch_id)
        print("defense_stage = ", self.defense_stage)
        print("offsets = ", self.offsets)
        print()



class TaskSetter:
    def __init__(self):
        try:
            self.task_dict = {}
            self.attack_name = ""
            self.task = Task("",0,0)
            self.share_memory_1 = sketch.MemoryManager()
            self.share_memory_2 = sketch.MemoryManager()
            self.interface = None
            self.bfrt_info = None
            self.runtime = None
            self.grpc_setup(1,'R2_D2')
        except Exception as e:
            print(traceback.format_exc())
            print(e, " when loading configure file.")
            exit(1)
    
    def grpc_setup(self, client_id=0, p4_name=None):
        '''
        Set up connection to gRPC server and bind
        Args: 
         - client_id Client ID
         - p4_name Name of P4 program, 'R2_D2' in this controller.
        '''
        grpc_addr = 'localhost:50052'

        self.interface = gc.ClientInterface(grpc_addr, client_id=client_id,device_id=0, notifications=None)
        self.interface.bind_pipeline_config(p4_name)
        self.bfrt_info = self.interface.bfrt_info_get()
        self.runtime = gc.Target(device_id=0, pipe_id=0xffff)

    # Add of defense tasks
    def add_task(self, attack_names):
        """
        Add defense task.

        params:
            attack_name: Attack.

        return
            null.
        """
        # global alloc_time
        # alloc_time = 0
        attack_names = attack_names.split() # Separation attack name
        output_string = ""
        for attack_name in attack_names:
            # Get attack code table
            payloads = Data.get_payload(attack_name)
            self.task = Task(attack_name, payloads["task_id"], payloads["sketch_id"])

            # Setting up attack defense task information
            self.task.task_name = attack_name
            self.task.task_id = payloads["task_id"]
            self.task.sketch_id = payloads["sketch_id"]
            self.task.defense_stage = payloads["defense_stage"]

            # Generating Attack Defense Mission Control commands
            output_string += "# Add " + attack_name + "\n"
            output_string += self.generate_attack(payloads)

            # add
            self.task_dict[attack_name] = copy.deepcopy(self.task)

            # self.task_dict[attack_name].print_task()

        return output_string
    
    # Release of defense tasks
    def release_task(self, attack_names):
        """
        Release defense task.

        params:
            attack_name: Attack.

        return
            control commands.
        """
        # global alloc_time
        # alloc_time = 0
        attack_names = attack_names.split() # Separation attack name
        output_string = ""
        for attack_name in attack_names:
            # Get attack code table
            payloads = Data.get_payload(attack_name)

            flag_stage = 0
            for t in self.task_dict:
                if t == attack_name:
                    flag_stage = self.task_dict[attack_name].defense_stage

            if flag_stage == 1:
                output_string += "# Release " + attack_name + "\n"
                output_string += self.release_stage1(attack_name, payloads)
                del self.task_dict[attack_name]
                if payloads["use_sketch"] == True:
                    self.share_memory_1.deallocate(payloads["sketch_id"])
            elif flag_stage == 2:
                output_string += "# Release " + attack_name + "\n"
                output_string += self.release_stage2(attack_name, payloads)
                del self.task_dict[attack_name]
                if payloads["use_sketch"] == True:
                    self.share_memory_2.deallocate(payloads["sketch_id"])
            else:
                print("{} is not deployed!".format(attack_name))
        
        return output_string
            

        



    def generate_attack(self, payloads):
        """
        Generate defense task control commands.

        params:
            payloads: Attack code information.

        return
            control commands.
        """
        if payloads["defense_stage"] == 1:
            return self.generate_stage_1(payloads)
        elif payloads["defense_stage"] == 2:
            return self.generate_stage_2(payloads)
        


    def generate_payload_1(self, payloads):
        """
        Generate control commands that match the attack defense task.

        params:
            in_or_out: Switch ports to consider for flag defense tasks.
                    1 is a port that considers only external traffic inflow;
                    2 is a port that considers both external and internal traffic inflow
            payloads: Attack code information.

        return
            control commands.
        """
        output_string = ""
        switch_ports = Data.get_payload("switch_ports")
        in_or_out = payloads["in_or_out"]
        payload_task = payloads["payload"]
        sketch_length = payloads["sketch_length"]

        batch_match = []
        batch_action = []
        batch_match_dy = []
        batch_action_dy = []
        match_first_id = self.bfrt_info.table_get("Ingress.match_first_id")
        dynamic_hash = self.bfrt_info.table_get("Ingress.dynamic_hash")

        for payload in payload_task:
            if in_or_out == 2:
                for port in switch_ports["in"]:
                    # dynamic hash selection
                    match_dy = dynamic_hash.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port),
                                                    gc.KeyTuple('hdr.ipv4.protocol', int(payload[0],16)),
                                                    gc.KeyTuple('meta.states', low = payload[1], high = payload[2]),
                                                    gc.KeyTuple('$MATCH_PRIORITY',payload[3])])
                    if payloads["defense_scheme"] == 1:
                        action_dy = dynamic_hash.make_data([], "Ingress.set_five_hash")
                    elif payloads["defense_scheme"] == 2:
                        action_dy = dynamic_hash.make_data([], "Ingress.set_three_hash")
                    else:
                        action_dy = dynamic_hash.make_data([], "Ingress.set_session_hash")

                    batch_match_dy.append(match_dy)
                    batch_action_dy.append(action_dy)

                    if payloads["defense_scheme"] == 1:
                        output_string += "bfrt.R2_D2.pipe.Ingress.dynamic_hash.add_with_set_five_hash(ingress_port="
                    elif payloads["defense_scheme"] == 2:
                        output_string += "bfrt.R2_D2.pipe.Ingress.dynamic_hash.add_with_set_three_hash(ingress_port="
                    else:
                        output_string += "bfrt.R2_D2.pipe.Ingress.dynamic_hash.add_with_set_session_hash(ingress_port="

                    output_string += str(port)
                    output_string += ", protocol=" + str(payload[0])
                    output_string += ", states_start=" + str(payload[1])
                    output_string += ", states_end=" + str(payload[2])
                    output_string += ", match_priority=" + str(payload[3])
                    output_string += ")\n"

                    # match task
                    match = match_first_id.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port),
                                                    gc.KeyTuple('hdr.ipv4.protocol', int(payload[0],16)),
                                                    gc.KeyTuple('meta.states', low = payload[1], high = payload[2]),
                                                    gc.KeyTuple('$MATCH_PRIORITY',payload[3])])
                    action = match_first_id.make_data([gc.DataTuple('task_id', payloads["task_id"]),
                                                gc.DataTuple('sketch_id', payloads["sketch_id"]),
                                                gc.DataTuple('option', payloads["defense_scheme"]),
                                                gc.DataTuple('in_or_out', 0),
                                                gc.DataTuple('mask_index', (sketch_length if sketch_length==0 else sketch_length - 1)),
                                                gc.DataTuple('meter_id', payloads["meter_id"]),
                                                gc.DataTuple('param', payloads["param"])],
                                                "Ingress.set_id")
                    batch_match.append(match)
                    batch_action.append(action)

                    output_string += "bfrt.R2_D2.pipe.Ingress.match_first_id.add_with_set_id(ingress_port="
                    output_string += str(port)
                    output_string += ", protocol=" + str(payload[0])
                    output_string += ", states_start=" + str(payload[1])
                    output_string += ", states_end=" + str(payload[2])
                    output_string += ", task_id=" + str(payloads["task_id"])
                    output_string += ", sketch_id=" + str(payloads["sketch_id"])
                    output_string += ", option=" + str(payloads["defense_scheme"])
                    output_string += ", in_or_out=" + str(0)
                    output_string += ", mask_index = " + hex(sketch_length if sketch_length==0 else sketch_length - 1)
                    output_string += ", meter_id=" + str(payloads["meter_id"])
                    output_string += ", param=" + str(payloads["param"])
                    output_string += ", match_priority=" + str(payload[3])
                    output_string += ")\n"
                in_or_out -= 1
            elif in_or_out == 1:
                for port in switch_ports["out"]:
                    # dynamic hash selection
                    match_dy = dynamic_hash.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port),
                                                    gc.KeyTuple('hdr.ipv4.protocol', int(payload[0],16)),
                                                    gc.KeyTuple('meta.states', low = payload[1], high = payload[2]),
                                                    gc.KeyTuple('$MATCH_PRIORITY',payload[3])])
                    if payloads["defense_scheme"] == 1:
                        action_dy = dynamic_hash.make_data([], "Ingress.set_five_hash")
                    elif payloads["defense_scheme"] == 2:
                        action_dy = dynamic_hash.make_data([], "Ingress.set_three_hash")
                    else:
                        action_dy = dynamic_hash.make_data([], "Ingress.set_five_hash")

                    batch_match_dy.append(match_dy)
                    batch_action_dy.append(action_dy)

                    if payloads["defense_scheme"] == 1:
                        output_string += "bfrt.R2_D2.pipe.Ingress.dynamic_hash.add_with_set_five_hash(ingress_port="
                    elif payloads["defense_scheme"] == 2:
                        output_string += "bfrt.R2_D2.pipe.Ingress.dynamic_hash.add_with_set_three_hash(ingress_port="
                    else:
                        output_string += "bfrt.R2_D2.pipe.Ingress.dynamic_hash.add_with_set_five_hash(ingress_port="

                    output_string += str(port)
                    output_string += ", protocol=" + str(payload[0])
                    output_string += ", states_start=" + str(payload[1])
                    output_string += ", states_end=" + str(payload[2])
                    output_string += ", match_priority=" + str(payload[3])
                    output_string += ")\n"

                    # match task
                    match = match_first_id.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port),
                                                    gc.KeyTuple('hdr.ipv4.protocol', int(payload[0],16)),
                                                    gc.KeyTuple('meta.states', low = payload[1], high = payload[2]),
                                                    gc.KeyTuple('$MATCH_PRIORITY',payload[3])])
                    action = match_first_id.make_data([gc.DataTuple('task_id', payloads["task_id"]),
                                                gc.DataTuple('sketch_id', payloads["sketch_id"]),
                                                gc.DataTuple('option', payloads["defense_scheme"]),
                                                gc.DataTuple('in_or_out', 0),
                                                gc.DataTuple('mask_index', (sketch_length if sketch_length==0 else sketch_length - 1)),
                                                gc.DataTuple('meter_id', payloads["meter_id"]),
                                                gc.DataTuple('param', (payloads["param"] if payloads["defense_scheme"]!=4 else 1))],
                                                "Ingress.set_id")
                    batch_match.append(match)
                    batch_action.append(action)

                    output_string += \
                    "bfrt.R2_D2.pipe.Ingress.match_first_id.add_with_set_id(ingress_port="
                    output_string += str(port)
                    output_string += ", protocol=" + str(payload[0])
                    output_string += ", states_start=" + str(payload[1])
                    output_string += ", states_end=" + str(payload[2])
                    output_string += ", task_id=" + str(payloads["task_id"])
                    output_string += ", sketch_id=" + str(payloads["sketch_id"])
                    output_string += ", option=" + str(payloads["defense_scheme"])
                    output_string += ", in_or_out=" + str(1)
                    output_string += ", mask_index = " + hex(sketch_length if sketch_length==0 else sketch_length - 1)
                    output_string += ", meter_id=" + str(payloads["meter_id"])
                    output_string += ", param=" + str((payloads["param"] if payloads["defense_scheme"]!=4 else 1))
                    output_string += ", match_priority=" + str(payload[3])
                    output_string += ")\n"
        
        try:
            dynamic_hash.entry_add(self.runtime, batch_match_dy, batch_action_dy, bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
        except gc.BfruntimeRpcException as e:
            # The error list should only have one error since the write
            # request should have failed at the very first error
            error_list = e.sub_errors_get()
            logger.info("Expected error length = %d Received %d",
                        1, len(error_list))
            assert len(error_list) == 1

        try:
            match_first_id.entry_add(self.runtime, batch_match, batch_action, bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
        except gc.BfruntimeRpcException as e:
            # The error list should only have one error since the write
            # request should have failed at the very first error
            error_list = e.sub_errors_get()
            logger.info("Expected error length = %d Received %d",
                        1, len(error_list))
            assert len(error_list) == 1

        return output_string
    
    def generate_payload_2(self, payloads):
        """
        Generate control commands that match the attack defense task.

        params:
            in_or_out: Switch ports to consider for flag defense tasks.
                    1 is a port that considers only external traffic inflow;
                    2 is a port that considers both external and internal traffic inflow
            payloads: Attack code information.

        return
            control commands.
        """
        output_string = ""
        switch_ports = Data.get_payload("switch_ports")

        in_or_out = payloads["in_or_out"]
        payload_task = payloads["payload"]
        sketch_length = payloads["sketch_length"]

        batch_match = []
        batch_action = []
        batch_match_dy = []
        batch_action_dy = []
        match_second_id = self.bfrt_info.table_get("Egress.match_second_id")
        dynamic_hash_second = self.bfrt_info.table_get("Egress.dynamic_hash_second")

        for payload in payload_task:
            if in_or_out == 2:
                for port in switch_ports["out"]:
                    # dynamic hash selection
                    match_dy = dynamic_hash_second.make_key([gc.KeyTuple('eg_intr_md.egress_port', port),
                                                gc.KeyTuple('hdr.ports.src_port', value=payload[0], mask=payload[1]),
                                                gc.KeyTuple('hdr.ports.dst_port', value=payload[2], mask=payload[3]),
                                                gc.KeyTuple('$MATCH_PRIORITY', payload[4])])
                    
                    if payloads["defense_scheme"] == 1:
                        action_dy = dynamic_hash_second.make_data([], "Egress.set_five_hash")
                    elif payloads["defense_scheme"] == 2:
                        action_dy = dynamic_hash_second.make_data([], "Egress.set_three_hash")
                    else:
                        action_dy = dynamic_hash_second.make_data([], "Egress.set_session_hash")

                    batch_match_dy.append(match_dy)
                    batch_action_dy.append(action_dy)

                    if payloads["defense_scheme"] == 1:
                        output_string += "bfrt.R2_D2.pipe.Egress.dynamic_hash_second.add_with_set_five_hash(egress_port="
                    elif payloads["defense_scheme"] == 2:
                        output_string += "bfrt.R2_D2.pipe.Egress.dynamic_hash_second.add_with_set_three_hash(egress_port="
                    else:
                        output_string += "bfrt.R2_D2.pipe.Egress.dynamic_hash_second.add_with_set_session_hash(egress_port="

                    output_string += str(port)
                    output_string += ", src_port=" + str(payload[0])
                    output_string += ", src_port_mask=" + str(payload[1])
                    output_string += ", dst_port=" + str(payload[2])
                    output_string += ", dst_port_mask=" + str(payload[3])
                    output_string += ", match_priority=" + str(payload[4])
                    output_string += ")\n"

                    # match task
                    match = match_second_id.make_key([gc.KeyTuple('eg_intr_md.egress_port', port),
                                                gc.KeyTuple('hdr.ports.src_port', value=payload[0], mask=payload[1]),
                                                gc.KeyTuple('hdr.ports.dst_port', value=payload[2], mask=payload[3]),
                                                gc.KeyTuple('$MATCH_PRIORITY', payload[4])])
                    action = match_second_id.make_data([gc.DataTuple('task_id', payloads["task_id"]),
                                                gc.DataTuple('sketch_id', payloads["sketch_id"]),
                                                gc.DataTuple('option', payloads["defense_scheme"]),
                                                gc.DataTuple('in_or_out', 0),
                                                gc.DataTuple('mask_index', (sketch_length if sketch_length==0 else sketch_length - 1)),
                                                gc.DataTuple('meter_id', payloads["meter_id"]),
                                                gc.DataTuple('param', payloads["param"])],
                                                "Egress.set_id")
                    batch_match.append(match)
                    batch_action.append(action)

                    output_string += "bfrt.R2_D2.pipe.Egress.match_second_id.add_with_set_id(egress_port="
                    output_string += str(port)
                    output_string += ", src_port=" + str(payload[0])
                    output_string += ", src_port_mask=" + str(payload[1])
                    output_string += ", dst_port=" + str(payload[2])
                    output_string += ", dst_port_mask=" + str(payload[3])
                    output_string += ", task_id=" + str(payloads["task_id"])
                    output_string += ", sketch_id=" + str(payloads["sketch_id"])
                    output_string += ", option=" + str(payloads["defense_scheme"])
                    output_string += ", in_or_out=" + str(0)
                    output_string += ", mask_index = " + hex(sketch_length if sketch_length==0 else sketch_length - 1)
                    output_string += ", meter_id=" + str(payloads["meter_id"])
                    output_string += ", param=" + str(payloads["param"])
                    output_string += ", match_priority=" + str(payload[4])
                    output_string += ")\n"
                in_or_out -= 1
            elif in_or_out == 1:
                for port in switch_ports["in"]:
                    # dynamic hash selection
                    match_dy = dynamic_hash_second.make_key([gc.KeyTuple('eg_intr_md.egress_port', port),
                                                gc.KeyTuple('hdr.ports.src_port', value=payload[0], mask=payload[1]),
                                                gc.KeyTuple('hdr.ports.dst_port', value=payload[2], mask=payload[3]),
                                                gc.KeyTuple('$MATCH_PRIORITY', payload[4])])
                    
                    if payloads["defense_scheme"] == 1:
                        action_dy = dynamic_hash_second.make_data([], "Egress.set_five_hash")
                    elif payloads["defense_scheme"] == 2:
                        action_dy = dynamic_hash_second.make_data([], "Egress.set_three_hash")
                    else:
                        action_dy = dynamic_hash_second.make_data([], "Egress.set_five_hash")

                    batch_match_dy.append(match_dy)
                    batch_action_dy.append(action_dy)

                    if payloads["defense_scheme"] == 1:
                        output_string += "bfrt.R2_D2.pipe.Egress.dynamic_hash_second.add_with_set_five_hash(egress_port="
                    elif payloads["defense_scheme"] == 2:
                        output_string += "bfrt.R2_D2.pipe.Egress.dynamic_hash_second.add_with_set_three_hash(egress_port="
                    else:
                        output_string += "bfrt.R2_D2.pipe.Egress.dynamic_hash_second.add_with_set_five_hash(egress_port="

                    output_string += str(port)
                    output_string += ", src_port=" + str(payload[0])
                    output_string += ", src_port_mask=" + str(payload[1])
                    output_string += ", dst_port=" + str(payload[2])
                    output_string += ", dst_port_mask=" + str(payload[3])
                    output_string += ", match_priority=" + str(payload[4])
                    output_string += ")\n"

                    # match task
                    match = match_second_id.make_key([gc.KeyTuple('eg_intr_md.egress_port', port),
                                                gc.KeyTuple('hdr.ports.src_port', value=payload[0], mask=payload[1]),
                                                gc.KeyTuple('hdr.ports.dst_port', value=payload[2], mask=payload[3]),
                                                gc.KeyTuple('$MATCH_PRIORITY', payload[4])])
                    action = match_second_id.make_data([gc.DataTuple('task_id', payloads["task_id"]),
                                                gc.DataTuple('sketch_id', payloads["sketch_id"]),
                                                gc.DataTuple('option', payloads["defense_scheme"]),
                                                gc.DataTuple('in_or_out', 0),
                                                gc.DataTuple('mask_index', (sketch_length if sketch_length==0 else sketch_length - 1)),
                                                gc.DataTuple('meter_id', payloads["meter_id"]),
                                                gc.DataTuple('param', (payloads["param"] if payloads["defense_scheme"]!=4 else 1))],
                                                "Egress.set_id")
                    batch_match.append(match)
                    batch_action.append(action)

                    output_string += "bfrt.R2_D2.pipe.Egress.match_second_id.add_with_set_id(egress_port="
                    output_string += str(port)
                    output_string += ", src_port=" + str(payload[0])
                    output_string += ", src_port_mask=" + str(payload[1])
                    output_string += ", dst_port=" + str(payload[2])
                    output_string += ", dst_port_mask=" + str(payload[3])
                    output_string += ", task_id=" + str(payloads["task_id"])
                    output_string += ", sketch_id=" + str(payloads["sketch_id"])
                    output_string += ", option=" + str(payloads["defense_scheme"])
                    output_string += ", in_or_out=" + str(1)
                    output_string += ", mask_index = " + hex(sketch_length if sketch_length==0 else sketch_length - 1)
                    output_string += ", meter_id=" + str(payloads["meter_id"])
                    output_string += ", param=" + str((payloads["param"] if payloads["defense_scheme"]!=4 else 1))
                    output_string += ", match_priority=" + str(payload[4])
                    output_string += ")\n"

        try:
            dynamic_hash_second.entry_add(self.runtime, batch_match_dy, batch_action_dy, bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
        except gc.BfruntimeRpcException as e:
            # The error list should only have one error since the write
            # request should have failed at the very first error
            error_list = e.sub_errors_get()
            logger.info("Expected error length = %d Received %d",
                        1, len(error_list))
            assert len(error_list) == 1
        
        try:
            match_second_id.entry_add(self.runtime, batch_match, batch_action, bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
        except gc.BfruntimeRpcException as e:
            # The error list should only have one error since the write
            # request should have failed at the very first error
            error_list = e.sub_errors_get()
            logger.info("Expected error length = %d Received %d",
                        1, len(error_list))
            assert len(error_list) == 1

        return output_string

    def generate_stage_1(self, payloads):
        """
        Generate Stage 1 defense task control commands.

        params:
            payloads: Attack code information.
        
        return
            control commands.
        """
        output_string = self.generate_payload_1(payloads)

        if payloads["use_sketch"] == True:
            start_time = time.time()
            task_sketch = self.share_memory_1.allocate(payloads["sketch_id"], payloads["sketch_row"], payloads["sketch_length"])
            end_time = time.time()
            global alloc_time
            alloc_time = alloc_time + (end_time - start_time)

            offsets = task_sketch.offsets
            self.task.offsets = offsets

            tlb_set_index1 = self.bfrt_info.table_get("Ingress.tlb_set_index1")
            match1 = [tlb_set_index1.make_key([gc.KeyTuple('meta.sketch_id', payloads["sketch_id"])])]
            action1 = [tlb_set_index1.make_data([gc.DataTuple('offset1', 0 if offsets[0] == -1 else offsets[0]),
                                                 gc.DataTuple('offset2', 0 if offsets[1] == -1 else offsets[1]),
                                                 gc.DataTuple('offset3', 0 if offsets[2] == -1 else offsets[2]),
                                                 gc.DataTuple('offset4', 0 if offsets[3] == -1 else offsets[3])],
                                                 "Ingress.set_index_1")]

            offsets_str = ""
            for i in range(4):
                if offsets[i] != -1:
                    offsets_str += ", offset" + str(i + 1) + "=" + hex(offsets[i])
                else:
                    offsets_str += ", offset" + str(i + 1) + "=" + hex(0)
            
            output_string += \
            "bfrt.R2_D2.pipe.Ingress.tlb_set_index1.add_with_set_index_1(sketch_id=" + \
                str(payloads["sketch_id"]) + offsets_str + ")\n"

            add_table_entires = []

            for i in range(4):
                if offsets[i] != -1:
                    match_first_sketch_row = self.bfrt_info.table_get("Ingress.match_first_sketch_row{}".format(i + 1))
                    add_table_entires.append([
                        match_first_sketch_row,
                        [match_first_sketch_row.make_key([gc.KeyTuple('meta.sketch_id', payloads["sketch_id"])])],
                        [match_first_sketch_row.make_data([], "Ingress.noaction")]
                    ])
                    output_string += \
                    "bfrt.R2_D2.pipe.Ingress.match_first_sketch_row" + str(i + 1) + ".add_with_noaction(sketch_id=" + str(payloads["sketch_id"]) + ")\n"
            try:
                tlb_set_index1.entry_add(self.runtime, match1, action1, bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
                for item in add_table_entires:
                    item[0].entry_add(self.runtime, item[1], item[2], bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
            except gc.BfruntimeRpcException as e:
                # The error list should only have one error since the write
                # request should have failed at the very first error
                error_list = e.sub_errors_get()
                logger.info("Expected error length = %d Received %d",
                            1, len(error_list))
                assert len(error_list) == 1
                
        # print(insert)
        if payloads["table_drop"] == True:
            first_result_drop = self.bfrt_info.table_get("Ingress.first_result_drop")

            match1 = [first_result_drop.make_key([gc.KeyTuple('meta.task_id', payloads["task_id"]),
                                        gc.KeyTuple('meta.result', low=payloads["result_start"], high=payloads["result_end"]),
                                        gc.KeyTuple('meta.color', low=payloads["color_start"] if payloads["token"] else 0, high=payloads["color_end"] if payloads["token"] else 3),
                                        gc.KeyTuple('$MATCH_PRIORITY', 1)])]
            action1 = [first_result_drop.make_data([], "Ingress.drop")]

            output_string += \
            "bfrt.R2_D2.pipe.Ingress.first_result_drop.add_with_drop(task_id=" + str(payloads["task_id"]) + ", result_start=" + str(payloads["result_start"]) + ", result_end=" + str(payloads["result_end"])
            
            if payloads["token"] == True:
                output_string += ", color_start=" + str(payloads["color_start"]) + ", color_end=" + str(payloads["color_end"])
            else:
                output_string += ", color_start=0, color_end=3"
                
            output_string += ", match_priority=1" + ")\n"

            if payloads["token"] == True:
                output_string += "bfrt.R2_D2.pipe.Ingress.Rate_Limiting.mod(meter_index=" + str(payloads["meter_id"]) + ", meter_spec_cir_kbps=" + str(payloads["spec_cir_pps"]) + ", meter_spec_pir_kbps=" + str(payloads["spec_pir_pps"]) + ", meter_spec_cbs_kbits=" + str(payloads["spec_cbs_pkts"]) + ", meter_spec_pbs_kbits=" + str(payloads["spec_pbs_pkts"]) + ")\n"
            try:
                first_result_drop.entry_add(self.runtime, match1, action1, bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
            except gc.BfruntimeRpcException as e:
                # The error list should only have one error since the write
                # request should have failed at the very first error
                error_list = e.sub_errors_get()
                logger.info("Expected error length = %d Received %d",
                            1, len(error_list))
                assert len(error_list) == 1

        return output_string


    def generate_stage_2(self, payloads):
        """
        Generate Stage 2 defense task control commands.

        params:
            payloads: Attack code information.
        
        return
            control commands.
        """
        output_string = self.generate_payload_2(payloads)

        if payloads["use_sketch"] == True:
            start_time = time.time()
            task_sketch = self.share_memory_2.allocate(payloads["sketch_id"], payloads["sketch_row"], payloads["sketch_length"])
            end_time = time.time()
            global alloc_time
            alloc_time = alloc_time + (end_time - start_time)

            offsets = task_sketch.offsets
            self.task.offsets = offsets

            tlb_set_index2 = self.bfrt_info.table_get("Egress.tlb_set_index2")
            match2 = [tlb_set_index2.make_key([gc.KeyTuple('meta.sketch_id', payloads["sketch_id"])])]
            action2 = [tlb_set_index2.make_data([gc.DataTuple('offset1', 0 if offsets[0] == -1 else offsets[0]),
                                                 gc.DataTuple('offset2', 0 if offsets[1] == -1 else offsets[1]),
                                                 gc.DataTuple('offset3', 0 if offsets[2] == -1 else offsets[2]),
                                                 gc.DataTuple('offset4', 0 if offsets[3] == -1 else offsets[3])],
                                                 "Egress.set_index_2")]

            offsets_str = ""
            for i in range(4):
                if offsets[i] != -1:
                    offsets_str += ", offset" + str(i + 1) + "=" + hex(offsets[i])
                else:
                    offsets_str += ", offset" + str(i + 1) + "=" + hex(0)

            output_string += \
            "bfrt.R2_D2.pipe.Egress.tlb_set_index2.add_with_set_index_2(sketch_id=" + \
                str(payloads["sketch_id"]) + offsets_str + ")\n"

            add_table_entires = []

            for i in range(4):
                if offsets[i] != -1:
                    match_second_sketch_row = self.bfrt_info.table_get("Egress.match_second_sketch_row{}".format(i + 1))
                    add_table_entires.append([
                        match_second_sketch_row,
                        [match_second_sketch_row.make_key([gc.KeyTuple('meta.sketch_id', payloads["sketch_id"])])],
                        [match_second_sketch_row.make_data([], "Egress.noaction")]
                    ])
                    output_string += \
                    "bfrt.R2_D2.pipe.Egress.match_second_sketch_row" + str(i + 1) + ".add_with_noaction(sketch_id=" + str(payloads["sketch_id"]) + ")\n"
            try:
                tlb_set_index2.entry_add(self.runtime, match2, action2, bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
                for item in add_table_entires:
                    item[0].entry_add(self.runtime, item[1], item[2], bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
            except gc.BfruntimeRpcException as e:
                # The error list should only have one error since the write
                # request should have failed at the very first error
                error_list = e.sub_errors_get()
                logger.info("Expected error length = %d Received %d",
                            1, len(error_list))
                assert len(error_list) == 1
                
        # print(insert)
        if payloads["table_drop"] == True:
            second_result_drop = self.bfrt_info.table_get("Egress.second_result_drop")

            match2 = [second_result_drop.make_key([gc.KeyTuple('meta.task_id', payloads["task_id"]),
                                        gc.KeyTuple('meta.result', low=payloads["result_start"], high=payloads["result_end"]),
                                        gc.KeyTuple('meta.color', low=payloads["color_start"] if payloads["token"] else 0, high=payloads["color_end"] if payloads["token"] else 3),
                                        gc.KeyTuple('$MATCH_PRIORITY', 1)])]
            action2 = [second_result_drop.make_data([], "Egress.drop")]

            output_string += \
            "bfrt.R2_D2.pipe.Egress.second_result_drop.add_with_drop(task_id=" + str(payloads["task_id"]) + ", result_start=" + str(payloads["result_start"]) + ", result_end=" + str(payloads["result_end"]) 
            if payloads["token"] == True:
                output_string += ", color_start=" + str(payloads["color_start"]) + ", color_end=" + str(payloads["color_end"])
            else:
                output_string += ", color_start=0, color_end=3"
                
            output_string += ", match_priority=1" + ")\n"

            if payloads["token"] == True:
                output_string += "bfrt.R2_D2.pipe.Egress.Rate_Limiting.mod(meter_index=" + str(payloads["meter_id"]) + ", meter_spec_cir_kbps=" + str(payloads["spec_cir_pps"]) + ", meter_spec_pir_kbps=" + str(payloads["spec_pir_pps"]) + ", meter_spec_cbs_kbits=" + str(payloads["spec_cbs_pkts"]) + ", meter_spec_pbs_kbits=" + str(payloads["spec_pbs_pkts"]) + ")\n"

            try:
                second_result_drop.entry_add(self.runtime, match2, action2, bfruntime_pb2.WriteRequest.ROLLBACK_ON_ERROR)
            except gc.BfruntimeRpcException as e:
                # The error list should only have one error since the write
                # request should have failed at the very first error
                error_list = e.sub_errors_get()
                logger.info("Expected error length = %d Received %d",
                            1, len(error_list))
                assert len(error_list) == 1

        return output_string

    def release_stage1(self, attack_name, payloads):
        """
        Release Stage 1 defense task control commands.

        params:
            task: class Task
        
        return
            control commands.
        """
        output_string = ""
        switch_ports = Data.get_payload("switch_ports")
        in_or_out = payloads["in_or_out"]
        payload_task = payloads["payload"]
        sketch_length = payloads["sketch_length"]

        batch_match_dy = []
        dynamic_hash = self.bfrt_info.table_get("Ingress.dynamic_hash")
        batch_match = []
        match_first_id = self.bfrt_info.table_get("Ingress.match_first_id")

        for payload in payload_task:
            if in_or_out == 2:
                for port in switch_ports["in"]:
                    match_dy = dynamic_hash.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port),
                                                    gc.KeyTuple('hdr.ipv4.protocol', int(payload[0],16)),
                                                    gc.KeyTuple('meta.states', low = payload[1], high = payload[2]),
                                                    gc.KeyTuple('$MATCH_PRIORITY',payload[3])])
                    batch_match_dy.append(match_dy)

                    output_string += "bfrt.R2_D2.pipe.Ingress.dynamic_hash.delete(ingress_port="
                    output_string += str(port)
                    output_string += ", protocol=" + str(payload[0])
                    output_string += ", states_start=" + str(payload[1])
                    output_string += ", states_end=" + str(payload[2])
                    output_string += ", match_priority=" + str(payload[3])
                    output_string += ")\n"


                    match = match_first_id.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port),
                                                    gc.KeyTuple('hdr.ipv4.protocol', int(payload[0],16)),
                                                    gc.KeyTuple('meta.states', low = payload[1], high = payload[2]),
                                                    gc.KeyTuple('$MATCH_PRIORITY',payload[3])])
                    batch_match.append(match)
                    
                    output_string += "bfrt.R2_D2.pipe.Ingress.match_first_id.delete(ingress_port="
                    output_string += str(port)
                    output_string += ", protocol=" + str(payload[0])
                    output_string += ", states_start=" + str(payload[1])
                    output_string += ", states_end=" + str(payload[2])
                    output_string += ", match_priority=" + str(payload[3])
                    output_string += ")\n"
                in_or_out -= 1
            elif in_or_out == 1:
                for port in switch_ports["out"]:
                    match_dy = dynamic_hash.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port),
                                                    gc.KeyTuple('hdr.ipv4.protocol', int(payload[0],16)),
                                                    gc.KeyTuple('meta.states', low = payload[1], high = payload[2]),
                                                    gc.KeyTuple('$MATCH_PRIORITY',payload[3])])
                    batch_match_dy.append(match_dy)

                    output_string += "bfrt.R2_D2.pipe.Ingress.dynamic_hash.delete(ingress_port="
                    output_string += str(port)
                    output_string += ", protocol=" + str(payload[0])
                    output_string += ", states_start=" + str(payload[1])
                    output_string += ", states_end=" + str(payload[2])
                    output_string += ", match_priority=" + str(payload[3])
                    output_string += ")\n"


                    match = match_first_id.make_key([gc.KeyTuple('ig_intr_md.ingress_port', port),
                                                    gc.KeyTuple('hdr.ipv4.protocol', int(payload[0],16)),
                                                    gc.KeyTuple('meta.states', low = payload[1], high = payload[2]),
                                                    gc.KeyTuple('$MATCH_PRIORITY',payload[3])])
                    batch_match.append(match)

                    output_string += \
                    "bfrt.R2_D2.pipe.Ingress.match_first_id.delete(ingress_port="
                    output_string += str(port)
                    output_string += ", protocol=" + str(payload[0])
                    output_string += ", states_start=" + str(payload[1])
                    output_string += ", states_end=" + str(payload[2])
                    output_string += ", match_priority=" + str(payload[3])
                    output_string += ")\n"
        try:
            dynamic_hash.entry_del(self.runtime, batch_match_dy)
        except gc.BfruntimeRpcException as e:
            # The error list should only have one error since the write
            # request should have failed at the very first error
            error_list = e.sub_errors_get()
            logger.info("Expected error length = %d Received %d",
                        1, len(error_list))
            assert len(error_list) == 1

        try:
            match_first_id.entry_del(self.runtime, batch_match)
        except gc.BfruntimeRpcException as e:
            # The error list should only have one error since the write
            # request should have failed at the very first error
            error_list = e.sub_errors_get()
            logger.info("Expected error length = %d Received %d",
                        1, len(error_list))
            assert len(error_list) == 1

        if payloads["use_sketch"] == True:
            tlb_set_index1 = self.bfrt_info.table_get("Ingress.tlb_set_index1")
            match1 = [tlb_set_index1.make_key([gc.KeyTuple('meta.sketch_id', payloads["sketch_id"])])]

            output_string += \
            "bfrt.R2_D2.pipe.Ingress.tlb_set_index1.delete(sketch_id=" + \
                str(payloads["sketch_id"]) + ")\n"

            del_table_entires = []
            
            for i in range(4):
                if self.task_dict[attack_name].offsets[i] != -1:
                    match_first_sketch_row = self.bfrt_info.table_get("Ingress.match_first_sketch_row{}".format(i + 1))
                    del_table_entires.append([
                        match_first_sketch_row,
                        [match_first_sketch_row.make_key([gc.KeyTuple('meta.sketch_id', payloads["sketch_id"])])]
                    ])

                    output_string += \
                    "bfrt.R2_D2.pipe.Ingress.match_first_sketch_row" + str(i + 1) + ".delete(sketch_id=" + str(payloads["sketch_id"]) + ")\n"
            try:
                tlb_set_index1.entry_del(self.runtime, match1)
                for item in del_table_entires:
                    item[0].entry_del(self.runtime, item[1])
            except gc.BfruntimeRpcException as e:
                # The error list should only have one error since the write
                # request should have failed at the very first error
                error_list = e.sub_errors_get()
                logger.info("Expected error length = %d Received %d",
                            1, len(error_list))
                assert len(error_list) == 1


        if payloads["table_drop"] == True:
            first_result_drop = self.bfrt_info.table_get("Ingress.first_result_drop")
            match1 = [first_result_drop.make_key([gc.KeyTuple('meta.task_id', payloads["task_id"]),
                                        gc.KeyTuple('meta.result', low=payloads["result_start"], high=payloads["result_end"]),
                                        gc.KeyTuple('meta.color', low=payloads["color_start"] if payloads["token"] else 0, high=payloads["color_end"] if payloads["token"] else 3),
                                        gc.KeyTuple('$MATCH_PRIORITY', 1)])]

            output_string += \
            "bfrt.R2_D2.pipe.Ingress.first_result_drop.delete(task_id=" + str(payloads["task_id"]) + ", result_start=" + str(payloads["result_start"]) + ", result_end=" + str(payloads["result_end"])
            
            if payloads["token"] == True:
                output_string += ", color_start=" + str(payloads["color_start"]) + ", color_end=" + str(payloads["color_end"])
            else:
                output_string += ", color_start=0, color_end=3"
                
            output_string += ", match_priority=1" + ")\n"
            try:
                first_result_drop.entry_del(self.runtime, match1)
            except gc.BfruntimeRpcException as e:
                # The error list should only have one error since the write
                # request should have failed at the very first error
                error_list = e.sub_errors_get()
                logger.info("Expected error length = %d Received %d",
                            1, len(error_list))
                assert len(error_list) == 1

        return output_string

    def release_stage2(self, attack_name, payloads):
        """
        Release Stage 2 defense task control commands.

        params:
            task: class Task
        
        return
            control commands.
        """
        output_string = ""
        switch_ports = Data.get_payload("switch_ports")

        in_or_out = payloads["in_or_out"]
        payload_task = payloads["payload"]
        sketch_length = payloads["sketch_length"]

        batch_match_dy = []
        dynamic_hash_second = self.bfrt_info.table_get("Egress.dynamic_hash_second")
        
        batch_match = []
        match_second_id = self.bfrt_info.table_get("Egress.match_second_id")

        for payload in payload_task:
            if in_or_out == 2:
                for port in switch_ports["out"]:
                    match_dy = dynamic_hash_second.make_key([gc.KeyTuple('eg_intr_md.egress_port', port),
                                                gc.KeyTuple('hdr.ports.src_port', value=payload[0], mask=payload[1]),
                                                gc.KeyTuple('hdr.ports.dst_port', value=payload[2], mask=payload[3]),
                                                gc.KeyTuple('$MATCH_PRIORITY',payload[4])])
                    batch_match_dy.append(match_dy)

                    output_string += "bfrt.R2_D2.pipe.Egress.dynamic_hash_second.delete(egress_port="
                    output_string += str(port)
                    output_string += ", src_port=" + str(payload[0])
                    output_string += ", src_port_mask=" + str(payload[1])
                    output_string += ", dst_port=" + str(payload[2])
                    output_string += ", dst_port_mask=" + str(payload[3])
                    output_string += ", match_priority=" + str(payload[4])
                    output_string += ")\n"


                    match = match_second_id.make_key([gc.KeyTuple('eg_intr_md.egress_port', port),
                                                gc.KeyTuple('hdr.ports.src_port', value=payload[0], mask=payload[1]),
                                                gc.KeyTuple('hdr.ports.dst_port', value=payload[2], mask=payload[3]),
                                                gc.KeyTuple('$MATCH_PRIORITY',payload[4])])
                    batch_match.append(match)

                    output_string += "bfrt.R2_D2.pipe.Egress.match_second_id.delete(egress_port="
                    output_string += str(port)
                    output_string += ", src_port=" + str(payload[0])
                    output_string += ", src_port_mask=" + str(payload[1])
                    output_string += ", dst_port=" + str(payload[2])
                    output_string += ", dst_port_mask=" + str(payload[3])
                    output_string += ", match_priority=" + str(payload[4])
                    output_string += ")\n"
                in_or_out -= 1
            elif in_or_out == 1:
                for port in switch_ports["in"]:
                    match_dy = dynamic_hash_second.make_key([gc.KeyTuple('eg_intr_md.egress_port', port),
                                                gc.KeyTuple('hdr.ports.src_port', value=payload[0], mask=payload[1]),
                                                gc.KeyTuple('hdr.ports.dst_port', value=payload[2], mask=payload[3]),
                                                gc.KeyTuple('$MATCH_PRIORITY',payload[4])])
                    batch_match_dy.append(match_dy)

                    output_string += "bfrt.R2_D2.pipe.Egress.dynamic_hash_second.delete(egress_port="
                    output_string += str(port)
                    output_string += ", src_port=" + str(payload[0])
                    output_string += ", src_port_mask=" + str(payload[1])
                    output_string += ", dst_port=" + str(payload[2])
                    output_string += ", dst_port_mask=" + str(payload[3])
                    output_string += ", match_priority=" + str(payload[4])
                    output_string += ")\n"


                    match = match_second_id.make_key([gc.KeyTuple('eg_intr_md.egress_port', port),
                                                gc.KeyTuple('hdr.ports.src_port', value=payload[0], mask=payload[1]),
                                                gc.KeyTuple('hdr.ports.dst_port', value=payload[2], mask=payload[3]),
                                                gc.KeyTuple('$MATCH_PRIORITY',payload[4])])
                    batch_match.append(match)

                    output_string += "bfrt.R2_D2.pipe.Egress.match_second_id.delete(egress_port="
                    output_string += str(port)
                    output_string += ", src_port=" + str(payload[0])
                    output_string += ", src_port_mask=" + str(payload[1])
                    output_string += ", dst_port=" + str(payload[2])
                    output_string += ", dst_port_mask=" + str(payload[3])
                    output_string += ", match_priority=" + str(payload[4])
                    output_string += ")\n"
        try:
            dynamic_hash_second.entry_del(self.runtime, batch_match_dy)
        except gc.BfruntimeRpcException as e:
            # The error list should only have one error since the write
            # request should have failed at the very first error
            error_list = e.sub_errors_get()
            logger.info("Expected error length = %d Received %d",
                        1, len(error_list))
            assert len(error_list) == 1
            
        try:
            match_second_id.entry_del(self.runtime, batch_match)
        except gc.BfruntimeRpcException as e:
            # The error list should only have one error since the write
            # request should have failed at the very first error
            error_list = e.sub_errors_get()
            logger.info("Expected error length = %d Received %d",
                        1, len(error_list))
            assert len(error_list) == 1

        if payloads["use_sketch"] == True:
            tlb_set_index2 = self.bfrt_info.table_get("Egress.tlb_set_index2")
            match2 = [tlb_set_index2.make_key([gc.KeyTuple('meta.sketch_id', payloads["sketch_id"])])]

            output_string += \
            "bfrt.R2_D2.pipe.Egress.tlb_set_index2.delete(sketch_id=" + \
                str(payloads["sketch_id"]) + ")\n"
            
            del_table_entires = []
            
            for i in range(4):
                if self.task_dict[attack_name].offsets[i] != -1:
                    match_second_sketch_row = self.bfrt_info.table_get("Egress.match_second_sketch_row{}".format(i + 1))
                    del_table_entires.append([
                        match_second_sketch_row,
                        [match_second_sketch_row.make_key([gc.KeyTuple('meta.sketch_id', payloads["sketch_id"])])]
                    ])

                    output_string += \
                    "bfrt.R2_D2.pipe.Egress.match_second_sketch_row" + str(i + 1) + ".delete(sketch_id=" + str(payloads["sketch_id"]) + ")\n"
            try:
                tlb_set_index2.entry_del(self.runtime, match2)
                for item in del_table_entires:
                    item[0].entry_del(self.runtime, item[1])
            except gc.BfruntimeRpcException as e:
                # The error list should only have one error since the write
                # request should have failed at the very first error
                error_list = e.sub_errors_get()
                logger.info("Expected error length = %d Received %d",
                            1, len(error_list))
                assert len(error_list) == 1

        if payloads["table_drop"] == True:
            second_result_drop = self.bfrt_info.table_get("Egress.second_result_drop")
            match2 = [second_result_drop.make_key([gc.KeyTuple('meta.task_id', payloads["task_id"]),
                                        gc.KeyTuple('meta.result', low=payloads["result_start"], high=payloads["result_end"]),
                                        gc.KeyTuple('meta.color', low=payloads["color_start"] if payloads["token"] else 0, high=payloads["color_end"] if payloads["token"] else 3),
                                        gc.KeyTuple('$MATCH_PRIORITY', 1)])]

            output_string += \
            "bfrt.R2_D2.pipe.Egress.second_result_drop.delete(task_id=" + str(payloads["task_id"]) + ", result_start=" + str(payloads["result_start"]) + ", result_end=" + str(payloads["result_end"]) 
            if payloads["token"] == True:
                output_string += ", color_start=" + str(payloads["color_start"]) + ", color_end=" + str(payloads["color_end"])
            else:
                output_string += ", color_start=0, color_end=3"
                
            output_string += ", match_priority=1" + ")\n"
            try:
                second_result_drop.entry_del(self.runtime, match2)
            except gc.BfruntimeRpcException as e:
                # The error list should only have one error since the write
                # request should have failed at the very first error
                error_list = e.sub_errors_get()
                logger.info("Expected error length = %d Received %d",
                            1, len(error_list))
                assert len(error_list) == 1

        return output_string