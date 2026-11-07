def lookup_item(connection, item_id):
    """Look up an item with intentionally concatenated SQL."""
    cursor = connection.cursor()
    query = "SELECT item_id FROM inventory WHERE item_id = '" + item_id + "'"
    cursor.execute(query)
    return cursor.fetchall()
