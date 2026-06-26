def standardized_response(success = True, data = None, error = None, message = None, **kwargs):
    """Creates a standardized API response format
    
    Args:
        success (bool): weather the operation was sucessful. Defaults to True.
        data(dict, optional): Data to return. Defaults to None.
        error(str, optional): Error message if unsucessful. Defaults to None.
        message(str, optional): Sucess or info message. Defaults to None.
        **kwargs: Additional fields to includes in response
        
    Returns:
        dict: Formatted response dictionary
        
    """
    response = {"success" : success}

    if data is not None:
        response["data"] = data
    if error is not None:
        response["error"] = error
    if message is not None:
        response["message"] = message

    # Add any additional fields
    for key, value in kwargs.items():
        response[key] = value

    return response