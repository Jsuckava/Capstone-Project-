import re

file_path = r'c:\Users\DELL\Downloads\Capstone-Project-BlockChain-BlockGo-Backup-2\client-app\Controllers\AuthController.cs'
with open(file_path, 'r') as f:
    content = f.read()

# Replace DBNull assignments with explicit parameter types
def replace_param(match):
    prefix = match.group(1) # e.g. updateProfile.Parameters.
    name = match.group(2)   # e.g. "name"
    val = match.group(3)    # e.g. !string.IsNullOrEmpty(name) ? (object)name : DBNull.Value
    
    # Determine type based on name
    npgsql_type = "NpgsqlTypes.NpgsqlDbType.Text"
    if "curriculumId" in name or "academicSectionId" in name:
        npgsql_type = "NpgsqlTypes.NpgsqlDbType.Bigint"
        if "academicSectionId" in name: npgsql_type = "NpgsqlTypes.NpgsqlDbType.Integer"
    elif "dob" in name:
        npgsql_type = "NpgsqlTypes.NpgsqlDbType.Date"
    elif "yearLevel" in name:
        npgsql_type = "NpgsqlTypes.NpgsqlDbType.Text" # Assuming it's a string, e.g. "1"
        
    return f'{prefix}Add(new NpgsqlParameter({name}, {npgsql_type}) {{ Value = {val} }})'

# Regex to match:  cmd.Parameters.AddWithValue("name", value_expression);
new_content = re.sub(r'(\w+\.Parameters\.)AddWithValue\(([^,]+),\s*(.+?DBNull\.Value.+?)\)', replace_param, content)

with open(file_path, 'w') as f:
    f.write(new_content)
print("Replaced DBNull AddWithValue occurrences!")
