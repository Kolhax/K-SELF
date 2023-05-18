"""Sherlock Notify Module

This module defines the objects for notifying the caller about the
results of queries.
"""
from result import QueryStatus
from colorama import Fore, Style, init


class QueryNotify():
    """Query Notify Object.

    Base class that describes methods available to notify the results of
    a query.
    It is intended that other classes inherit from this base class and
    override the methods to implement specific functionality.
    """
    def __init__(self, result=None):
        """Create Query Notify Object.

        Contains information about a specific method of notifying the results
        of a query.

        Keyword Arguments:
        self                   -- This object.
        result                 -- Object of type QueryResult() containing
                                  results for this query.

        Return Value:
        Nothing.
        """

        self.result = result

        return

    def start(self, message=None, id_type='username'):
        """Notify Start.

        Notify method for start of query.  This method will be called before
        any queries are performed.  This method will typically be
        overridden by higher level classes that will inherit from it.

        Keyword Arguments:
        self                   -- This object.
        message                -- Object that is used to give context to start
                                  of query.
                                  Default is None.

        Return Value:
        Nothing.
        """

        return

    def update(self, result):
        """Notify Update.

        Notify method for query result.  This method will typically be
        overridden by higher level classes that will inherit from it.

        Keyword Arguments:
        self                   -- This object.
        result                 -- Object of type QueryResult() containing
                                  results for this query.

        Return Value:
        Nothing.
        """

        self.result = result

        return

    def finish(self, message=None):
        """Notify Finish.

        Notify method for finish of query.  This method will be called after
        all queries have been performed.  This method will typically be
        overridden by higher level classes that will inherit from it.

        Keyword Arguments:
        self                   -- This object.
        message                -- Object that is used to give context to start
                                  of query.
                                  Default is None.

        Return Value:
        Nothing.
        """

        return

    def __str__(self):
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        """
        result = str(self.result)

        return result


class QueryNotifyPrint(QueryNotify):
    """Query Notify Print Object.

    Query notify class that prints results.
    """
    def __init__(self, result=None, verbose=False, print_found_only=False,
                 skip_check_errors=False, color=True):
        """Create Query Notify Print Object.

        Contains information about a specific method of notifying the results
        of a query.

        Keyword Arguments:
        self                   -- This object.
        result                 -- Object of type QueryResult() containing
                                  results for this query.
        verbose                -- Boolean indicating whether to give verbose output.
        print_found_only       -- Boolean indicating whether to only print found sites.
        color                  -- Boolean indicating whether to color terminal output

        Return Value:
        Nothing.
        """

        # Colorama module's initialization.
        init(autoreset=True)

        super().__init__(result)
        self.verbose = verbose
        self.print_found_only = print_found_only
        self.skip_check_errors = skip_check_errors
        self.color = color

        return

    def start(self, message, id_type):
        """Notify Start.

        Will print the title to the standard output.

        Keyword Arguments:
        self                   -- This object.
        message                -- String containing username that the series
                                  of queries are about.

        Return Value:
        Nothing.
        """

        title = f"Checking {id_type}"
        if self.color:
            print(Style.BRIGHT + Fore.GREEN + "[" +
                Fore.YELLOW + "*" +
                Fore.GREEN + f"] {title}" +
                Fore.WHITE + f" {message}" +
                Fore.GREEN + " on:")
        else:
            print(f"[*] {title} {message} on:")

        return

    def get_additional_data_text(self, items, prepend=''):
        text = ''
        for num, item in enumerate(items):
            box_symbol = '┣╸' if num != len(items) - 1 else '┗╸'

            if type(item) == tuple:
                field_name, field_value = item
                if field_value.startswith('[\''):
                    is_last_item = num == len(items) - 1
                    prepend_symbols = ' '*3 if is_last_item else ' ┃ '
                    field_value = self.get_additional_data_text(eval(field_value), prepend_symbols)
                text += f'\n{prepend}{box_symbol}{field_name}: {field_value}'
            else:
                text += f'\n{prepend}{box_symbol} {item}'

        return text

    def update(self, result):
        """Notify Update.

        Will print the query result to the standard output.

        Keyword Arguments:
        self                   -- This object.
        result                 -- Object of type QueryResult() containing
                                  results for this query.

        Return Value:
        Nothing.
        """
        self.result = result

        if self.verbose == False or self.result.query_time is None:
            response_time_text = ""
        else:
            response_time_text = f" [{round(self.result.query_time * 1000)} ms]"

        if not self.result.ids_data:
            ids_data_text = ""
        else:
            ids_data_text = self.get_additional_data_text(self.result.ids_data.items(), ' ')

        # Output to the terminal is desired.
        if result.status == QueryStatus.CLAIMED:
            if self.color:
                print((Style.BRIGHT + Fore.WHITE + "[" +
                       Fore.GREEN + "+" +
                       Fore.WHITE + "]" +
                       response_time_text +
                       Fore.GREEN +
                       f" {self.result.site_name}: " +
                       Style.RESET_ALL +
                       f"{self.result.site_url_user}" +
                       f"{ids_data_text}"))
            else:
                print(f"[+]{response_time_text} {self.result.site_name}: {self.result.site_url_user} {ids_data_text}")
        elif result.status == QueryStatus.AVAILABLE:
            if not self.print_found_only:
                if self.color:
                    print((Style.BRIGHT + Fore.WHITE + "[" +
                           Fore.RED + "-" +
                           Fore.WHITE + "]" +
                           response_time_text +
                           Fore.GREEN + f" {self.result.site_name}:" +
                           Fore.YELLOW + " Not Found!"))
                else:
                    print(f"[-]{response_time_text} {self.result.site_name}: Not Found!")
        elif result.status == QueryStatus.UNKNOWN:
            if not self.skip_check_errors:
                if self.color:
                    print(Style.BRIGHT + Fore.WHITE + "[" +
                          Fore.RED + "?" +
                          Fore.WHITE + "]" +
                          Fore.GREEN + f" {self.result.site_name}:" +
                          Fore.RED + f" {self.result.context}" +
                          Fore.YELLOW + f" ")
                else:
                    print(f"[-] {self.result.site_name}: {self.result.context} {ids_data_text}")
        elif result.status == QueryStatus.ILLEGAL:
            if not self.print_found_only:
                msg = "Illegal Username Format For This Site!"
                if self.color:
                    print((Style.BRIGHT + Fore.WHITE + "[" +
                           Fore.RED + "-" +
                           Fore.WHITE + "]" +
                           Fore.GREEN + f" {self.result.site_name}:" +
                           Fore.YELLOW + f" {msg}"))
                else:
                    print(f"[-] {self.result.site_name} {msg}")
        else:
            #It should be impossible to ever get here...
            raise ValueError(f"Unknown Query Status '{str(result.status)}' for "
                             f"site '{self.result.site_name}'")

        return

    def __str__(self):
        """Convert Object To String.

        Keyword Arguments:
        self                   -- This object.

        Return Value:
        Nicely formatted string to get information about this object.
        """
        result = str(self.result)

        return result
