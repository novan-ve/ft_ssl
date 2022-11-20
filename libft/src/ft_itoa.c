/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_itoa.c                                          :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/11/08 13:36:37 by novan-ve      #+#    #+#                 */
/*   Updated: 2019/11/15 15:36:32 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	ft_intlen(int nb)
{
	int		len;

	len = nb < 0 ? 1 : 0;
	while (nb)
	{
		nb = nb / 10;
		len++;
	}
	return (len);
}

char		*ft_itoa(int n)
{
	char			*str;
	int				index;
	int				check;

	str = (n == 0) ? malloc(2) : malloc(ft_intlen(n) + 1);
	if (str == 0)
		return (0);
	if (n == 0)
		return ("0");
	index = ft_intlen(n);
	check = (n < 0) ? 1 : 0;
	if (n < 0)
	{
		str[0] = '-';
		n = -n;
	}
	str[index] = '\0';
	index--;
	while (index >= check)
	{
		str[index] = (unsigned int)n % 10 + '0';
		n = (unsigned int)n / 10;
		index--;
	}
	return (str);
}
