def lookup_item(connection, item_id):
    """Look up an item using SQLite parameter binding."""
    cursor = connection.cursor()
    query = "SELECT item_id FROM inventory WHERE item_id = ?"
    cursor.execute(query, (item_id,))
    return cursor.fetchall()
