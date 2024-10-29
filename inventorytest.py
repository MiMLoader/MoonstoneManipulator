import re
import json

# Define the InventoryItem class
class InventoryItem:
    def __init__(self, quantity, name, attributes):
        self.quantity = quantity
        self.name = name
        self.attributes = attributes

    def __repr__(self):
        return f"InventoryItem(quantity={self.quantity}, name={self.name}, attributes={self.attributes})"

# Read the inventory.txt file
with open('inventory.txt', 'r') as file:
    content = file.read()

# Extract the data after '"data\":['
match = re.search(r'"data\\":\[\s*(.*)', content, re.DOTALL)
if not match:
    raise ValueError("No data found in the file.")

data_content = match.group(1).strip()

# Remove any trailing commas and whitespace at the end
data_content = data_content.rstrip(',\n\r ')

# Ensure the data ends with a closing bracket
if not data_content.endswith(']'):
    data_content += ']'

# Replace escaped quotes \" with actual quotes "
data_content = data_content.replace('\\"', '"')

# Wrap the data_content in square brackets to form a valid JSON array
data_content = '[' + data_content + ']'

# Parse the data using json.loads
try:
    data = json.loads(data_content)
except json.JSONDecodeError as e:
    print("Error parsing JSON:", e)
    raise

# Create InventoryItem instances
inventory_items = []
for item in data:
    # Each item is [[quantity], [name], [attributes]]
    quantity = item[0][0]
    name = item[1][0]
    attributes = item[2][0]
    inventory_items.append(InventoryItem(quantity, name, attributes))

# Print the inventory items
for item in inventory_items:
    print(item)