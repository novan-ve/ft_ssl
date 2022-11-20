/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_putstr_fd.c                                     :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/11/01 15:51:56 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/14 13:06:36 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_putstr_fd(char *s, int fd)
{
	char	ch;

	if (s)
		while (*s)
		{
			ch = *s;
			ft_putchar_fd(ch, fd);
			s++;
		}
}
