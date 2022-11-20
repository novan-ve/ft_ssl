/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_putulong_fd.c                                   :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/11/01 16:03:18 by novan-ve      #+#    #+#                 */
/*   Updated: 2022/09/28 13:44:46 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_putulong_fd(unsigned long long n, int fd)
{
	char c;

	if (n > 9) {
		if (ft_putulong_fd(n / 10, fd) < 0) {
			return (-1);
		}
		if (ft_putulong_fd(n % 10, fd) < 0) {
			return (-1);
		}
	}
	else {
		c = n + '0';
		if (write(fd, &c, 1) < 0) {
			return (-1);
		}
	}
	return (0);
}
