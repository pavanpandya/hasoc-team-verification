proxy = 'http://127.0.0.1:5500/frontend/Dashboard';

async function add_user() {
    Swal.fire({
        title: 'Create User',
        html: `<input type="name" id="name" class="swal2-input" placeholder="Username">
            <input type="email" id="Email" class="swal2-input" placeholder="Email">
            <input type="password" id="password" class="swal2-input" placeholder="Password"><br><br>
            <input type="checkbox" id="isadmin" class="mr-3" placeholder="admin access">Admin Access`,
        confirmButtonText: 'Create',
        focusConfirm: false,
        preConfirm: () => {
            const name = Swal.getPopup().querySelector('#name').value;
            const email = Swal.getPopup().querySelector('#Email').value;
            const password = Swal.getPopup().querySelector('#password').value;
            const isadmin = Swal.getPopup().querySelector('#isadmin').checked;
            //console.log(isadmin)
            return fetch(proxy + '/users.html', {
                method: 'post',
                body: JSON.stringify({ 'name': name, 'email': email, 'password': password, 'isadmin': isadmin }),
                headers: {
                    'Content-type': 'application/json',
                    "x-access-token": localStorage.getItem("token")
                }

            })
                .then(response => {
                    //console.log(response)
                    if (response.status != 200) { throw new Error(response.statusText) }
                    return response.json()
                })
                .catch(error => { Swal.showValidationMessage(`Request failed: ${error}`) })
        },
        allowOutsideClick: () => !Swal.isLoading()
    }).then((result) => {
        if (result.isConfirmed) {
            Swal.fire({
                title: 'User Created Successfully!',
                icon: 'success',
                timer: 2000,
                showConfirmButton: false
            })
            display_users();
        }
    })
}


async function display_users() {
    //console.log('in user function');
    url = proxy + '/users.html';
    const response = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    });
    if (response.status == 200) {
        var data = await response.json();
        data = data['users'];
        let tab = ''

        //console.log(data)
        for (usr in data) {
            //console.log(data[usr].adminAccess)
            if (data[usr].adminAccess === true) {
                icon = '<i class="fas fa-user-cog mr-3"></i>'
            } else {
                icon = '<i class="fas fa-user mr-3"></i>'
            }
            tab += `<tr>
            <td>${data[usr]._id}</td>
            <td>${data[usr].name}</td>
            <td>${data[usr].email}</td>
            <td>${data[usr].verified}</td>
            </tr>`
        }
        document.getElementById("user_table").innerHTML = tab;
        //console.log('displaying');
    }
}


async function display_tweets_by_users(name) {
    url = proxy + '/api/tweet_by_user?name=' + name
    let response = await fetch(url, {
        headers: {
            "x-access-token": localStorage.getItem("token")
        }
    })
    if (response.status === 200) {
        var data = await response.json();
        data = data.data
        //console.log(data)
        if (data.length === 0) {
            tab = `<h1 class="my-3">No Assigned Tweets.......!</h1>`
        } else {
            //console.log(data)
            tab = ``
            for (key in data) {
                tab += `<tr>
            <td class="align-middle">${data[key].story}</td>
            <td class="align-middle">${data[key].tweet_id}</td>
            <td class="align-middle">${data[key].tweet}</td>
            <td class="align-middle">
                <div class=" container justify-content-center">`

                if (data[key].annotated_by.includes(name)) {
                    icon = `<i class="fas fa-check-circle mr-3 fa-2x">`
                } else { icon = `<i class="fas fa-clock fa-2x"></i>` }
                tab += icon
                tab += `</i></div></td>
            <td class="align-middle"><button class="btn btn-info" disabled>View</button></td>
        </tr>`
            }

        }
        document.getElementById("show_tweets_for_user").innerHTML = tab;
    }

}

getPagination('#table-id');
//getPagination('.table-class');
//getPagination('table');

/*					PAGINATION 
- on change max rows select options fade out all rows gt option value mx = 5
- append pagination list as per numbers of rows / max rows option (20row/5= 4pages )
- each pagination li on click -> fade out all tr gt max rows * li num and (5*pagenum 2 = 10 rows)
- fade out all tr lt max rows * li num - max rows ((5*pagenum 2 = 10) - 5)
- fade in all tr between (10*PageNum) and (10*pageNum)- 10 
*/


function getPagination(table) {
    var lastPage = 1;
            var totalRows = $(table + ' tbody tr').length; // numbers of rows
            $(table + ' tr:gt(0)').each(function () {
                // each TR in  table and not the header
                trnum++; // Start Counter
                if (trnum > 10) {
                    // if tr number gt 10
                    $(this).hide(); // fade it out
                }
                if (trnum <= 10) {
                    $(this).show();
                } // else fade in Important in case if it ..
            }); //  was fade out to fade it in
            if (totalRows > 10) {
                // if tr total rows gt max rows option
                var pagenum = Math.ceil(totalRows / 10); // ceil total(rows/10) to get ..
                //	numbers of pages
                for (var i = 1; i <= pagenum;) {
                    // for each page append pagination li
                    $('.pagination #prev')
                        .before(
                            '<li data-page="' +
                            i +
                            '">\<span>' +
                            i++ +
                            '<span class="sr-only">(current)</span></span>\</li>'
                        )
                        .show();
                } // end for i
            } // end if row count > max rows
            $('.pagination [data-page="1"]').addClass('active'); // add active class to the first li
            $('.pagination li').on('click', function (evt) {
                // on click each page
                evt.stopImmediatePropagation();
                evt.preventDefault();
                var pageNum = $(this).attr('data-page'); // get it's number

                if (pageNum == 'prev') {
                    if (lastPage == 1) {
                        return;
                    }
                    pageNum = --lastPage;
                }
                if (pageNum == 'next') {
                    if (lastPage == $('.pagination li').length - 2) {
                        return;
                    }
                    pageNum = ++lastPage;
                }

                lastPage = pageNum;
                var trIndex = 0; // reset tr counter
                $('.pagination li').removeClass('active'); // remove active class from all li
                $('.pagination [data-page="' + lastPage + '"]').addClass('active'); // add active class to the clicked
                // $(this).addClass('active');					// add active class to the clicked
                limitPagging();
                $(table + ' tr:gt(0)').each(function () {
                    // each tr in table not the header
                    trIndex++; // tr index counter
                    // if tr index gt 10*pageNum or lt 10*pageNum-10 fade if out
                    if (
                        trIndex > 10 * pageNum ||
                        trIndex <= 10 * pageNum - 10
                    ) {
                        $(this).hide();
                    } else {
                        $(this).show();
                    } //else fade in
                }); // end of for each tr in table
            }); // end of on click pagination list
            limitPagging();
        })
        .val(5)
        .change();

    // end of on select change

    // END OF PAGINATION
}

function limitPagging() {
    // alert($('.pagination li').length)

    if ($('.pagination li').length > 7) {
        if ($('.pagination li.active').attr('data-page') <= 3) {
            $('.pagination li:gt(5)').hide();
            $('.pagination li:lt(5)').show();
            $('.pagination [data-page="next"]').show();
        } if ($('.pagination li.active').attr('data-page') > 3) {
            $('.pagination li:gt(0)').hide();
            $('.pagination [data-page="next"]').show();
            for (let i = (parseInt($('.pagination li.active').attr('data-page')) - 2); i <= (parseInt($('.pagination li.active').attr('data-page')) + 2); i++) {
                $('.pagination [data-page="' + i + '"]').show();
            }
        }
    }
}

$(function () {
    // Just to append id number for each row
    $('table tr:eq(0)').prepend('<th> ID </th>');
    var id = 0;
    $('table tr:gt(0)').each(function () {
        id++;
        $(this).prepend('<td>' + id + '</td>');
    });
});
