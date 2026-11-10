class Sketch:
    def __init__(self, sketch_id, sketch_rows, sketch_length, offsets=None):
        self.sketch_id = sketch_id
        self.sketch_rows = sketch_rows
        self.sketch_length = sketch_length
        self.offsets = offsets if offsets else [-1, -1, -1, -1]

    def __repr__(self):
        return ("Sketch(id={}, rows={}, length={}, offsets={})".format(
                self.sketch_id, self.sketch_rows, self.sketch_length, self.offsets))

class MemoryManager:
    def __init__(self):
        # Initialize 4 arrays with 2^17 registers each, using a bitmap to represent usage
        self.memory_size = 2**17
        self.block_size = 2**12  # Block size to reduce bitmap length
        self.bitmap = [[0] * (self.memory_size // self.block_size) for _ in range(4)]
        self.sketches = []  # List to store allocated sketches

    def find_free_block(self, array_index, num_blocks):
        """Find a large enough contiguous free block in the bitmap"""
        free_blocks = 0
        start_block = -1
        for i in range(len(self.bitmap[array_index])):
            if self.bitmap[array_index][i] == 0:  # This block is free
                if start_block == -1:
                    start_block = i
                free_blocks += 1
                if free_blocks == num_blocks:
                    return start_block
            else:
                free_blocks = 0
                start_block = -1
        return -1

    def allocate(self, sketch_id, num_arrays, num_registers):
        if not (0 < num_arrays <= 4):
            raise ValueError("num_arrays should be between 1 and 4")
        
        num_blocks = num_registers // self.block_size
        selected_arrays = random.sample(range(4), num_arrays)  # Randomly select arrays
        
        offsets = [-1] * 4
        
        for array_index in selected_arrays:
            start_block = self.find_free_block(array_index, num_blocks)
            if start_block == -1:
                raise MemoryError("Not enough contiguous memory in array {}".format(array_index))
            
            # Mark blocks in the bitmap as used
            for i in range(start_block, start_block + num_blocks):
                self.bitmap[array_index][i] = 1
            
            # Calculate the actual starting position of the registers
            offsets[array_index] = start_block * self.block_size

        sketch = Sketch(
            sketch_id=sketch_id,
            sketch_rows=num_arrays,
            sketch_length=num_registers,
            offsets=offsets
        )
        
        # Store the allocated sketch
        self.sketches.append(sketch)

        return sketch

    def deallocate(self, sketch_id):
        """Deallocate memory associated with the given sketch_id"""
        sketch_to_deallocate = None
        
        # Find the sketch by sketch_id
        for sketch in self.sketches:
            if sketch.sketch_id == sketch_id:
                sketch_to_deallocate = sketch
                break
        
        if not sketch_to_deallocate:
            raise ValueError("Sketch with id {} not found".format(sketch_id))
        
        # Deallocate the memory used by this sketch
        for array_index, offset in enumerate(sketch_to_deallocate.offsets):
            if offset != -1:
                start_block = offset // self.block_size
                num_blocks = sketch_to_deallocate.sketch_length // self.block_size
                for i in range(start_block, start_block + num_blocks):
                    self.bitmap[array_index][i] = 0
        
        # Remove the sketch from the list
        self.sketches.remove(sketch_to_deallocate)

import random
if __name__ == "__main__":
    mm = MemoryManager()
    sketch = mm.allocate(sketch_id=1, num_arrays=2, num_registers=8192)
    print(sketch)

    mm.deallocate(1)
