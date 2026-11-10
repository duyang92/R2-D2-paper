p4 = bfrt.R2_D2.pipe
ipv4_lpm = p4.Ingress.ipv4_lpm

ipv4_lpm.clear()

dynamic_hash = p4.Ingress.dynamic_hash
match_first_id = p4.Ingress.match_first_id
tlb_set_index1 = p4.Ingress.tlb_set_index1
match_first_sketch_row1 = p4.Ingress.match_first_sketch_row1
match_first_sketch_row2 = p4.Ingress.match_first_sketch_row2
match_first_sketch_row3 = p4.Ingress.match_first_sketch_row3
match_first_sketch_row4 = p4.Ingress.match_first_sketch_row4
first_result_drop = p4.Ingress.first_result_drop
first_sketch_row1 = p4.Ingress.first_sketch_row1
first_sketch_row2 = p4.Ingress.first_sketch_row2
first_sketch_row3 = p4.Ingress.first_sketch_row3
first_sketch_row4 = p4.Ingress.first_sketch_row4
Rate_Limiting_1 = p4.Ingress.Rate_Limiting
dynamic_hash_second = p4.Egress.dynamic_hash_second
match_second_id = p4.Egress.match_second_id
tlb_set_index2 = p4.Egress.tlb_set_index2
match_second_sketch_row1 = p4.Egress.match_second_sketch_row1
match_second_sketch_row2 = p4.Egress.match_second_sketch_row2
match_second_sketch_row3 = p4.Egress.match_second_sketch_row3
match_second_sketch_row4 = p4.Egress.match_second_sketch_row4
second_result_drop = p4.Egress.second_result_drop
second_sketch_row1 = p4.Egress.second_sketch_row1
second_sketch_row2 = p4.Egress.second_sketch_row2
second_sketch_row3 = p4.Egress.second_sketch_row3
second_sketch_row4 = p4.Egress.second_sketch_row4
second_result_drop = p4.Egress.second_result_drop
Rate_Limiting_2 = p4.Egress.Rate_Limiting

dynamic_hash.clear()
match_first_id.clear()
tlb_set_index1.clear()
match_first_sketch_row1.clear()
match_first_sketch_row2.clear()
match_first_sketch_row3.clear()
match_first_sketch_row4.clear()
first_result_drop.clear()
first_sketch_row1.clear()
first_sketch_row2.clear()
first_sketch_row3.clear()
first_sketch_row4.clear()
Rate_Limiting_1.clear()
dynamic_hash_second.clear()
match_second_id.clear()
tlb_set_index2.clear()
match_second_sketch_row1.clear()
match_second_sketch_row2.clear()
match_second_sketch_row3.clear()
match_second_sketch_row4.clear()
second_result_drop.clear()
second_result_drop.clear()
second_sketch_row1.clear()
second_sketch_row2.clear()
second_sketch_row3.clear()
second_sketch_row4.clear()
Rate_Limiting_2.clear()